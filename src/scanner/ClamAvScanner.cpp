#include "warden/scanner/ClamAvScanner.h"

#include <clamav.h>

namespace {

warden::core::Severity severityFromSignatureName(const std::string &signatureName)
{
    const std::string normalized = warden::core::toLowerCopy(signatureName);

    if (normalized.find("ransom") != std::string::npos ||
        normalized.find("trojan") != std::string::npos ||
        normalized.find("backdoor") != std::string::npos) {
        return warden::core::Severity::Critical;
    }

    if (normalized.find("worm") != std::string::npos ||
        normalized.find("downloader") != std::string::npos ||
        normalized.find("dropper") != std::string::npos) {
        return warden::core::Severity::High;
    }

    if (normalized.find("pua") != std::string::npos ||
        normalized.find("adware") != std::string::npos) {
        return warden::core::Severity::Medium;
    }

    return warden::core::Severity::High;
}

} // namespace

namespace warden::scanner {

ClamAvScanner::ClamAvScanner()
    : m_engine(nullptr)
{
}

ClamAvScanner::~ClamAvScanner()
{
    if (m_engine != nullptr) {
        cl_engine_free(m_engine);
        m_engine = nullptr;
    }
}

std::filesystem::path ClamAvScanner::defaultDatabasePath()
{
    const char *databaseDirectory = cl_retdbdir();
    if (databaseDirectory == nullptr) {
        return {};
    }

    return std::filesystem::path(databaseDirectory);
}

bool ClamAvScanner::initialize(const std::filesystem::path &databasePath)
{
    if (m_engine != nullptr) {
        cl_engine_free(m_engine);
        m_engine = nullptr;
    }

    m_status = {};
    m_status.available = true;
    if (const char *version = cl_retver()) {
        m_status.version = version;
    }

    const std::filesystem::path resolvedDatabasePath = databasePath.empty() ? defaultDatabasePath() : databasePath;
    if (resolvedDatabasePath.empty()) {
        m_status.error = "ClamAV did not provide a default database directory.";
        return false;
    }

    m_status.databasePath = resolvedDatabasePath.string();

    const cl_error_t initResult = cl_init(CL_INIT_DEFAULT);
    if (initResult != CL_SUCCESS) {
        m_status.error = std::string("cl_init failed: ") + cl_strerror(initResult);
        return false;
    }

    m_engine = cl_engine_new();
    if (m_engine == nullptr) {
        m_status.error = "cl_engine_new failed to allocate a scanning engine.";
        return false;
    }

    cl_engine_set_num(m_engine, CL_ENGINE_MAX_SCANSIZE, 512LL * 1024LL * 1024LL);
    cl_engine_set_num(m_engine, CL_ENGINE_MAX_FILESIZE, 256LL * 1024LL * 1024LL);
    cl_engine_set_num(m_engine, CL_ENGINE_MAX_FILES, 5000);
    cl_engine_set_num(m_engine, CL_ENGINE_MAX_RECURSION, 32);

    unsigned int signatures = 0;
    const std::string databasePathString = resolvedDatabasePath.string();
    const cl_error_t loadResult = cl_load(
        databasePathString.c_str(),
        m_engine,
        &signatures,
        CL_DB_STDOPT | CL_DB_PUA
    );
    if (loadResult != CL_SUCCESS) {
        cl_engine_free(m_engine);
        m_engine = nullptr;
        m_status.error = std::string("cl_load failed for ") + databasePathString + ": " + cl_strerror(loadResult);
        return false;
    }

    const cl_error_t compileResult = cl_engine_compile(m_engine);
    if (compileResult != CL_SUCCESS) {
        cl_engine_free(m_engine);
        m_engine = nullptr;
        m_status.error = std::string("cl_engine_compile failed: ") + cl_strerror(compileResult);
        return false;
    }

    m_status.initialized = true;
    m_status.signatures = signatures;
    return true;
}

ClamAvScanResult ClamAvScanner::scanFile(const std::filesystem::path &filePath,
                                         const std::string &sha256) const
{
    ClamAvScanResult result;
    if (m_engine == nullptr) {
        result.error = "ClamAV scanner was used before the engine was initialized.";
        return result;
    }

    const std::string filePathString = filePath.string();
    const char *virusName = nullptr;
    unsigned long scannedObjects = 0;
    cl_scan_options options {};
    options.general = CL_SCAN_GENERAL_HEURISTICS;
    options.parse = CL_SCAN_PARSE_ARCHIVE |
                    CL_SCAN_PARSE_ELF |
                    CL_SCAN_PARSE_HTML |
                    CL_SCAN_PARSE_MAIL |
                    CL_SCAN_PARSE_OLE2 |
                    CL_SCAN_PARSE_PE |
                    CL_SCAN_PARSE_PDF |
                    CL_SCAN_PARSE_SWF |
                    CL_SCAN_PARSE_XMLDOCS;
    options.heuristic = CL_SCAN_HEURISTIC_BROKEN |
                        CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE |
                        CL_SCAN_HEURISTIC_ENCRYPTED_DOC |
                        CL_SCAN_HEURISTIC_MACROS;

    const cl_error_t scanResult = cl_scanfile(
        filePathString.c_str(),
        &virusName,
        &scannedObjects,
        m_engine,
        &options
    );

    result.scanned = true;
    result.scannedObjects = scannedObjects;

    if (scanResult == CL_CLEAN || scanResult == CL_VERIFIED) {
        return result;
    }

    if (scanResult == CL_VIRUS) {
        result.infected = true;

        core::ThreatFinding finding;
        finding.name = virusName != nullptr ? virusName : "ClamAV signature match";
        finding.path = filePath;
        finding.threatType = core::ThreatType::ClamAvSignature;
        finding.severity = severityFromSignatureName(finding.name);
        finding.source = "ClamAV";
        finding.description = "ClamAV matched the file against its signature database.";
        finding.recommendedAction = "Quarantine the file and validate whether the detection is expected.";
        finding.sha256 = sha256;

        std::error_code fileSizeError;
        finding.fileSize = std::filesystem::file_size(filePath, fileSizeError);
        result.findings.push_back(std::move(finding));
        return result;
    }

    result.error = std::string("cl_scanfile failed for ") + filePathString + ": " + cl_strerror(scanResult);
    return result;
}

const ClamAvLoadStatus &ClamAvScanner::status() const
{
    return m_status;
}

} // namespace warden::scanner
