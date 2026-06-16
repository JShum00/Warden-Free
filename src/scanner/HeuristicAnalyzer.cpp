#include "warden/scanner/HeuristicAnalyzer.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <unordered_set>

namespace {

std::string toLowerAscii(const std::vector<unsigned char> &buffer)
{
    std::string output;
    output.reserve(buffer.size());

    for (unsigned char byte : buffer) {
        if (std::isprint(byte) != 0 || std::isspace(byte) != 0) {
            output.push_back(static_cast<char>(std::tolower(byte)));
        } else {
            output.push_back(' ');
        }
    }

    return output;
}

std::vector<unsigned char> readFileSample(const std::filesystem::path &filePath,
                                          const std::size_t maxBytes,
                                          std::string &errorMessage)
{
    std::ifstream stream(filePath, std::ios::binary);
    if (!stream) {
        errorMessage = "Unable to open file for heuristic analysis: " + filePath.string();
        return {};
    }

    std::vector<unsigned char> sample;
    sample.reserve(maxBytes);

    std::array<char, 8192> buffer {};
    while (stream.good() && sample.size() < maxBytes) {
        const std::size_t remaining = maxBytes - sample.size();
        const std::streamsize chunkSize = static_cast<std::streamsize>(std::min<std::size_t>(buffer.size(), remaining));
        stream.read(buffer.data(), chunkSize);
        const std::streamsize bytesRead = stream.gcount();

        if (bytesRead > 0) {
            sample.insert(sample.end(), buffer.begin(), buffer.begin() + bytesRead);
        }
    }

    if (stream.bad()) {
        errorMessage = "I/O error while reading sample bytes from " + filePath.string();
        return {};
    }

    return sample;
}

std::vector<unsigned char> readFileTail(const std::filesystem::path &filePath,
                                        const std::uintmax_t fileSize,
                                        const std::size_t maxBytes,
                                        std::string &errorMessage)
{
    if (fileSize == 0 || maxBytes == 0) {
        return {};
    }

    std::ifstream stream(filePath, std::ios::binary);
    if (!stream) {
        errorMessage = "Unable to open file tail for heuristic analysis: " + filePath.string();
        return {};
    }

    const std::size_t bytesToRead = static_cast<std::size_t>(std::min<std::uintmax_t>(fileSize, maxBytes));
    const std::uintmax_t startOffset = fileSize - bytesToRead;
    stream.seekg(static_cast<std::streamoff>(startOffset), std::ios::beg);
    if (!stream) {
        errorMessage = "Unable to seek to file tail for heuristic analysis: " + filePath.string();
        return {};
    }

    std::vector<unsigned char> buffer(bytesToRead);
    stream.read(reinterpret_cast<char *>(buffer.data()), static_cast<std::streamsize>(bytesToRead));
    const std::streamsize bytesRead = stream.gcount();
    if (bytesRead < 0 || stream.bad()) {
        errorMessage = "I/O error while reading sample tail bytes from " + filePath.string();
        return {};
    }

    buffer.resize(static_cast<std::size_t>(bytesRead));
    return buffer;
}

double calculateEntropy(const std::vector<unsigned char> &buffer)
{
    if (buffer.empty()) {
        return 0.0;
    }

    std::array<std::size_t, 256> frequencies {};
    for (const unsigned char byte : buffer) {
        ++frequencies[byte];
    }

    double entropy = 0.0;
    const double size = static_cast<double>(buffer.size());
    for (const std::size_t frequency : frequencies) {
        if (frequency == 0) {
            continue;
        }

        const double probability = static_cast<double>(frequency) / size;
        entropy -= probability * std::log2(probability);
    }

    return entropy;
}

bool looksBinary(const std::vector<unsigned char> &buffer)
{
    if (buffer.empty()) {
        return false;
    }

    std::size_t nonTextBytes = 0;
    for (const unsigned char byte : buffer) {
        if (byte == 0) {
            return true;
        }

        if (std::isprint(byte) == 0 && std::isspace(byte) == 0) {
            ++nonTextBytes;
        }
    }

    return static_cast<double>(nonTextBytes) / static_cast<double>(buffer.size()) > 0.30;
}

bool startsWithExecutableHeader(const std::vector<unsigned char> &buffer)
{
    if (buffer.size() >= 2 && buffer[0] == 'M' && buffer[1] == 'Z') {
        return true;
    }
    if (buffer.size() >= 4 && buffer[0] == 0x7f && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F') {
        return true;
    }

    return false;
}

bool hasExtension(const std::filesystem::path &path, const std::unordered_set<std::string> &extensions)
{
    const std::string extension = warden::core::toLowerCopy(path.extension().string());
    return extensions.find(extension) != extensions.end();
}

std::vector<std::string> normalizedPathComponents(const std::filesystem::path &filePath)
{
    std::vector<std::string> components;
    for (const auto &component : filePath) {
        components.push_back(warden::core::toLowerCopy(component.string()));
    }
    return components;
}

void appendUnique(std::vector<std::string> &destination, const std::string &value)
{
    if (std::find(destination.begin(), destination.end(), value) == destination.end()) {
        destination.push_back(value);
    }
}

std::string formatEntropy(const double entropy)
{
    std::ostringstream stream;
    stream << std::fixed << std::setprecision(2) << entropy;
    return stream.str();
}

struct FileTraits {
    std::string extension;
    bool looksExecutable {false};
    bool looksScript {false};
    bool sourceCode {false};
    bool documentation {false};
    bool image {false};
    bool archive {false};
    bool sharedLibrary {false};
    bool textual {false};
};

bool containsPathComponent(const std::vector<std::string> &components, const std::string &needle)
{
    return std::find(components.begin(), components.end(), needle) != components.end();
}

int scaledDevelopmentContextWeight(const int weight, const bool scanDevelopmentEnvironments)
{
    return scanDevelopmentEnvironments ? std::max(2, weight / 2) : weight;
}

FileTraits classifyFileTraits(const std::filesystem::path &filePath,
                              const std::vector<unsigned char> &sample,
                              const bool binaryLike)
{
    static const std::unordered_set<std::string> scriptExtensions = {
        ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".ps1", ".psm1",
        ".bat", ".cmd", ".sh", ".py", ".pl", ".rb"
    };
    static const std::unordered_set<std::string> sourceCodeExtensions = {
        ".py", ".cs", ".cpp", ".c", ".h", ".hpp", ".java", ".rs", ".go"
    };
    static const std::unordered_set<std::string> documentationExtensions = {
        ".md", ".markdown", ".rst", ".adoc", ".asciidoc", ".txt"
    };
    static const std::unordered_set<std::string> imageExtensions = {
        ".svg", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".tga", ".psd"
    };
    static const std::unordered_set<std::string> archiveExtensions = {
        ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".jar", ".nupkg", ".unitypackage"
    };
    static const std::unordered_set<std::string> libraryExtensions = {
        ".dll", ".so", ".dylib"
    };

    FileTraits traits;
    traits.extension = warden::core::toLowerCopy(filePath.extension().string());
    traits.looksExecutable = startsWithExecutableHeader(sample);
    traits.looksScript = scriptExtensions.find(traits.extension) != scriptExtensions.end();
    traits.sourceCode = sourceCodeExtensions.find(traits.extension) != sourceCodeExtensions.end();
    traits.documentation = documentationExtensions.find(traits.extension) != documentationExtensions.end();
    traits.image = imageExtensions.find(traits.extension) != imageExtensions.end();
    traits.archive = archiveExtensions.find(traits.extension) != archiveExtensions.end();
    traits.sharedLibrary = libraryExtensions.find(traits.extension) != libraryExtensions.end();
    traits.textual = traits.looksScript || traits.sourceCode || traits.documentation || traits.image || !binaryLike;
    return traits;
}

int contextualScoreReduction(const std::filesystem::path &filePath,
                             const FileTraits &traits,
                             const warden::core::ScanOptions &options,
                             std::vector<std::string> &evidence)
{
    const std::array<std::pair<const char *, int>, 11> developmentSegments {{
        {".venv", 12},
        {"venv", 12},
        {"site-packages", 12},
        {"node_modules", 12},
        {"library", 8},
        {"packages", 8},
        {"build", 8},
        {"dist", 8},
        {"obj", 8},
        {"target", 8},
        {"packagecache", 12}
    }};

    const std::vector<std::string> components = normalizedPathComponents(filePath);
    int reduction = 0;
    for (const auto &normalizedComponent : components) {
        for (const auto &[segment, weight] : developmentSegments) {
            if (normalizedComponent == segment || (std::string(segment) == "packagecache" && normalizedComponent.rfind("packagecache@", 0) == 0)) {
                reduction += scaledDevelopmentContextWeight(weight, options.scanDevelopmentEnvironments);
                evidence.push_back("Context reduction: development path segment '" + normalizedComponent +
                                   "' lowered the heuristic score.");
            }
        }
    }

    const auto underUnityLibrarySubtree = [&components](const std::unordered_set<std::string> &subdirectories) {
        for (std::size_t index = 0; index + 1 < components.size(); ++index) {
            if (components[index] == "library" && subdirectories.find(components[index + 1]) != subdirectories.end()) {
                return true;
            }
        }
        return false;
    };

    const bool underPackageCache = [&components]() {
        for (std::size_t index = 0; index < components.size(); ++index) {
            if (components[index] == "packagecache" || components[index].rfind("packagecache@", 0) == 0) {
                return true;
            }
            if (components[index] == "library" &&
                index + 1 < components.size() &&
                (components[index + 1] == "packagecache" || components[index + 1].rfind("packagecache@", 0) == 0)) {
                return true;
            }
        }
        return false;
    }();

    const bool underUnityGeneratedContent = underUnityLibrarySubtree(
        {"scriptassemblies", "artifacts", "bee", "burstcache", "shadercache", "statecache"}
    );
    const bool underTrustedPackageEcosystem = containsPathComponent(components, "site-packages") ||
                                              containsPathComponent(components, "node_modules") ||
                                              containsPathComponent(components, ".nuget") ||
                                              containsPathComponent(components, "nuget") ||
                                              containsPathComponent(components, "packages") ||
                                              underPackageCache;

    if (underPackageCache) {
        reduction += scaledDevelopmentContextWeight(12, options.scanDevelopmentEnvironments);
        evidence.push_back("Context reduction: Unity PackageCache content lowered the heuristic score.");
    } else if (underUnityGeneratedContent) {
        reduction += scaledDevelopmentContextWeight(10, options.scanDevelopmentEnvironments);
        evidence.push_back("Context reduction: Unity Library-generated content lowered the heuristic score.");
    }

    if (underPackageCache &&
        hasExtension(filePath, {".dll", ".cs", ".svg", ".png", ".jpg", ".jpeg", ".tga", ".psd"})) {
        reduction += scaledDevelopmentContextWeight(8, options.scanDevelopmentEnvironments);
        evidence.push_back("Context reduction: vendored Unity package asset type lowered the heuristic score.");
    }

    if (underTrustedPackageEcosystem && traits.sharedLibrary) {
        reduction += scaledDevelopmentContextWeight(8, options.scanDevelopmentEnvironments);
        evidence.push_back("Context reduction: library inside a trusted package ecosystem lowered the heuristic score.");
    }

    if (traits.sourceCode) {
        reduction += 12;
        evidence.push_back("Context reduction: source code files require additional corroboration before being treated as security findings.");
    }
    if (traits.documentation) {
        reduction += 18;
        evidence.push_back("Context reduction: documentation and example code are treated as informational unless corroborated.");
    }
    if (traits.image) {
        reduction += 18;
        evidence.push_back("Context reduction: image and asset files are not treated as execution-focused samples.");
    }
    if (traits.archive) {
        reduction += 10;
        evidence.push_back("Context reduction: archive formats often contain compressed data that inflates entropy.");
    }

    return std::min(reduction, 36);
}

double confidenceFromScore(const int adjustedScore)
{
    return std::clamp(static_cast<double>(adjustedScore) / 100.0, 0.0, 0.95);
}

warden::core::FindingCategory classificationFromConfidence(const double confidence)
{
    if (confidence <= 0.30) {
        return warden::core::FindingCategory::Informational;
    }
    if (confidence <= 0.50) {
        return warden::core::FindingCategory::Finding;
    }
    if (confidence <= 0.75) {
        return warden::core::FindingCategory::Warning;
    }

    return warden::core::FindingCategory::Threat;
}

warden::core::Severity severityCapFromConfidence(const double confidence)
{
    if (confidence <= 0.10) {
        return warden::core::Severity::Informational;
    }
    if (confidence <= 0.30) {
        return warden::core::Severity::Low;
    }
    if (confidence <= 0.50) {
        return warden::core::Severity::Medium;
    }
    if (confidence <= 0.75) {
        return warden::core::Severity::High;
    }

    return warden::core::Severity::Critical;
}

warden::core::Severity applyConfidenceSeverityCap(const warden::core::Severity baseSeverity,
                                                  const double confidence)
{
    const warden::core::Severity cappedSeverity = severityCapFromConfidence(confidence);
    return static_cast<warden::core::Severity>(
        std::min(static_cast<int>(baseSeverity), static_cast<int>(cappedSeverity))
    );
}

warden::core::Severity executionSeverityFromScore(const int adjustedScore)
{
    if (adjustedScore >= 90) {
        return warden::core::Severity::Critical;
    }
    if (adjustedScore >= 65) {
        return warden::core::Severity::High;
    }
    if (adjustedScore >= 30) {
        return warden::core::Severity::Medium;
    }

    return warden::core::Severity::Low;
}

warden::core::Severity executableEntropySeverityFromScore(const int adjustedScore)
{
    return adjustedScore >= 40 ? warden::core::Severity::Medium : warden::core::Severity::Low;
}

warden::core::Severity packerSeverityFromScore(const int adjustedScore)
{
    return adjustedScore >= 70 ? warden::core::Severity::High : warden::core::Severity::Medium;
}

double executableEntropyThreshold(const FileTraits &traits)
{
    return traits.sharedLibrary ? 7.35 : 7.20;
}

std::string executionFindingName(const std::vector<std::string> &triggeredRules)
{
    const auto hasRule = [&](const std::string &needle) {
        return std::find(triggeredRules.begin(), triggeredRules.end(), needle) != triggeredRules.end();
    };

    if (hasRule("powershell-encoded-command") ||
        hasRule("powershell-invoke-expression") ||
        hasRule("powershell-base64-decoder")) {
        return "Suspicious PowerShell execution indicators";
    }
    if (hasRule("lolbin-mshta") ||
        hasRule("lolbin-regsvr32") ||
        hasRule("lolbin-rundll32") ||
        hasRule("lolbin-powershell")) {
        return "Suspicious LOLBin execution indicators";
    }

    return "Suspicious command execution indicators";
}

bool containsWithinPrefix(const std::string &normalizedSample,
                          const std::string &needle,
                          const std::size_t prefixBytes)
{
    const std::size_t offset = normalizedSample.find(needle);
    return offset != std::string::npos && offset < std::min(prefixBytes, normalizedSample.size());
}

std::vector<std::size_t> matchOffsets(const std::string &normalizedSample, const std::string &needle)
{
    std::vector<std::size_t> offsets;
    std::size_t searchOffset = 0;
    while ((searchOffset = normalizedSample.find(needle, searchOffset)) != std::string::npos) {
        offsets.push_back(searchOffset);
        ++searchOffset;
    }
    return offsets;
}

std::optional<std::uint32_t> readLe16(const std::vector<unsigned char> &buffer, const std::size_t offset)
{
    if (offset + 1 >= buffer.size()) {
        return std::nullopt;
    }

    return static_cast<std::uint32_t>(buffer[offset]) |
           (static_cast<std::uint32_t>(buffer[offset + 1]) << 8U);
}

std::optional<std::uint32_t> readLe32(const std::vector<unsigned char> &buffer, const std::size_t offset)
{
    if (offset + 3 >= buffer.size()) {
        return std::nullopt;
    }

    return static_cast<std::uint32_t>(buffer[offset]) |
           (static_cast<std::uint32_t>(buffer[offset + 1]) << 8U) |
           (static_cast<std::uint32_t>(buffer[offset + 2]) << 16U) |
           (static_cast<std::uint32_t>(buffer[offset + 3]) << 24U);
}

std::optional<std::size_t> peEntryPointRawOffset(const std::vector<unsigned char> &buffer)
{
    if (buffer.size() < 0x40 || buffer[0] != 'M' || buffer[1] != 'Z') {
        return std::nullopt;
    }

    const auto peOffset = readLe32(buffer, 0x3c);
    if (!peOffset.has_value() || *peOffset + 0x18 >= buffer.size()) {
        return std::nullopt;
    }

    const std::size_t peHeaderOffset = *peOffset;
    if (buffer[peHeaderOffset] != 'P' ||
        buffer[peHeaderOffset + 1] != 'E' ||
        buffer[peHeaderOffset + 2] != 0 ||
        buffer[peHeaderOffset + 3] != 0) {
        return std::nullopt;
    }

    const auto sectionCount = readLe16(buffer, peHeaderOffset + 6);
    const auto sizeOfOptionalHeader = readLe16(buffer, peHeaderOffset + 20);
    if (!sectionCount.has_value() || !sizeOfOptionalHeader.has_value()) {
        return std::nullopt;
    }

    const std::size_t optionalHeaderOffset = peHeaderOffset + 24;
    const auto magic = readLe16(buffer, optionalHeaderOffset);
    const auto entryPointRva = readLe32(buffer, optionalHeaderOffset + 16);
    if (!magic.has_value() || !entryPointRva.has_value()) {
        return std::nullopt;
    }

    if (*magic != 0x10b && *magic != 0x20b) {
        return std::nullopt;
    }

    const std::size_t sectionTableOffset = optionalHeaderOffset + *sizeOfOptionalHeader;
    for (std::size_t index = 0; index < *sectionCount; ++index) {
        const std::size_t sectionOffset = sectionTableOffset + (index * 40);
        if (sectionOffset + 39 >= buffer.size()) {
            return std::nullopt;
        }

        const auto virtualSize = readLe32(buffer, sectionOffset + 8);
        const auto virtualAddress = readLe32(buffer, sectionOffset + 12);
        const auto rawSize = readLe32(buffer, sectionOffset + 16);
        const auto rawOffset = readLe32(buffer, sectionOffset + 20);
        if (!virtualSize.has_value() || !virtualAddress.has_value() || !rawSize.has_value() || !rawOffset.has_value()) {
            return std::nullopt;
        }

        const std::uint32_t span = std::max(*virtualSize, *rawSize);
        if (*entryPointRva < *virtualAddress || *entryPointRva >= (*virtualAddress + span)) {
            continue;
        }

        return static_cast<std::size_t>(*rawOffset + (*entryPointRva - *virtualAddress));
    }

    return std::nullopt;
}

bool hasMpressMarkerNearStructure(const std::vector<unsigned char> &headSample,
                                  const std::vector<unsigned char> &tailSample,
                                  const std::uintmax_t fileSize,
                                  std::vector<std::string> &evidence)
{
    constexpr std::size_t kBoundaryBytes = 4096;
    constexpr std::size_t kEntryPointWindowBytes = 4096;
    const std::string normalizedHeadSample = toLowerAscii(headSample);
    const std::vector<std::size_t> headOffsets = matchOffsets(normalizedHeadSample, "mpress");
    const std::optional<std::size_t> entryPointOffset = peEntryPointRawOffset(headSample);

    for (const std::size_t offset : headOffsets) {
        if (offset < kBoundaryBytes) {
            evidence.push_back("Matched string: MPRESS near file header");
            return true;
        }
        if (entryPointOffset.has_value() &&
            offset >= (*entryPointOffset > kEntryPointWindowBytes ? *entryPointOffset - kEntryPointWindowBytes : 0) &&
            offset <= (*entryPointOffset + kEntryPointWindowBytes)) {
            evidence.push_back("Matched string: MPRESS near PE entry point");
            return true;
        }
        if (fileSize <= headSample.size() && offset + 6 >= normalizedHeadSample.size() - std::min(kBoundaryBytes, normalizedHeadSample.size())) {
            evidence.push_back("Matched string: MPRESS near file end");
            return true;
        }
    }

    if (!tailSample.empty()) {
        const std::string normalizedTailSample = toLowerAscii(tailSample);
        if (normalizedTailSample.find("mpress") != std::string::npos) {
            evidence.push_back("Matched string: MPRESS near file end");
            return true;
        }
    }

    return false;
}

bool hasPeEntryPointAnomaly(const std::vector<unsigned char> &headSample,
                            const std::uintmax_t fileSize,
                            std::vector<std::string> &evidence)
{
    if (fileSize == 0) {
        return false;
    }

    const std::optional<std::size_t> entryPointOffset = peEntryPointRawOffset(headSample);
    if (!entryPointOffset.has_value()) {
        return false;
    }

    if (static_cast<double>(*entryPointOffset) >= static_cast<double>(fileSize) * 0.65) {
        evidence.push_back("PE entry point is unusually deep in the file.");
        return true;
    }

    return false;
}

bool shouldEvaluateExecutionStringRules(const FileTraits &traits)
{
    if (traits.documentation || traits.image || traits.archive) {
        return false;
    }

    return traits.looksScript || traits.looksExecutable;
}

std::optional<std::string> firstMatch(const std::string &normalizedSample,
                                      const std::vector<std::string> &needles)
{
    for (const auto &needle : needles) {
        if (normalizedSample.find(needle) != std::string::npos) {
            return needle;
        }
    }

    return std::nullopt;
}

void appendWeightedIndicator(std::vector<std::string> &triggeredRules,
                             std::vector<std::string> &evidence,
                             int &score,
                             const std::string &ruleId,
                             const int weight,
                             const std::string &evidenceLine)
{
    appendUnique(triggeredRules, ruleId);
    appendUnique(evidence, evidenceLine);
    score += weight;
}

warden::core::ThreatFinding makeFinding(const std::filesystem::path &filePath,
                                        const std::string &sha256,
                                        const std::string &name,
                                        const std::string &description,
                                        const std::string &operatorSummary,
                                        const std::string &recommendedAction,
                                        const warden::core::FindingCategory classification,
                                        const warden::core::Severity severity,
                                        const double confidenceScore,
                                        const double entropy,
                                        const std::uintmax_t fileSize,
                                        const std::vector<std::string> &triggeredRules,
                                        const std::vector<std::string> &evidence)
{
    warden::core::ThreatFinding finding;
    finding.name = name;
    finding.path = filePath;
    finding.threatType = warden::core::ThreatType::Heuristic;
    finding.classification = classification;
    finding.severity = severity;
    finding.source = "Warden Heuristics";
    finding.detectionEngine = "Warden Heuristics";
    finding.detectionSource = warden::core::DetectionSource::Heuristic;
    finding.description = description;
    finding.operatorSummary = operatorSummary;
    finding.recommendedAction = recommendedAction;
    finding.sha256 = sha256;
    finding.fileSize = fileSize;
    finding.entropy = entropy;
    finding.confidenceScore = confidenceScore;
    finding.triggeredRules = triggeredRules;
    finding.evidence = evidence;
    return finding;
}

} // namespace

namespace warden::scanner {

HeuristicScanResult HeuristicAnalyzer::analyzeFile(const std::filesystem::path &filePath,
                                                   const std::string &sha256,
                                                   const core::ScanOptions &options) const
{
    constexpr std::size_t kSampleBytes = 256 * 1024;
    constexpr std::size_t kTailBytes = 4096;

    HeuristicScanResult result;
    std::string errorMessage;
    const std::vector<unsigned char> sample = readFileSample(filePath, kSampleBytes, errorMessage);
    if (!errorMessage.empty()) {
        result.error = errorMessage;
        return result;
    }

    std::error_code fileSizeError;
    const std::uintmax_t fileSize = std::filesystem::file_size(filePath, fileSizeError);
    const std::uintmax_t resolvedFileSize = fileSizeError ? 0 : fileSize;
    result.binaryLike = looksBinary(sample);
    result.entropy = calculateEntropy(sample);

    const std::string normalizedSample = toLowerAscii(sample);
    const FileTraits traits = classifyFileTraits(filePath, sample, result.binaryLike);

    std::vector<std::string> contextualEvidence;
    const int scoreReduction = contextualScoreReduction(filePath, traits, options, contextualEvidence);

    if (shouldEvaluateExecutionStringRules(traits)) {
        int executionScore = 0;
        std::vector<std::string> triggeredRules;
        std::vector<std::string> evidence;

        if (const auto encodedPowerShell = firstMatch(normalizedSample, {
                "powershell.exe -enc",
                "powershell -enc",
                "-encodedcommand"
            }); encodedPowerShell.has_value()) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "powershell-encoded-command",
                                    30,
                                    "Matched string: " + *encodedPowerShell);
        }

        if (normalizedSample.find("invoke-expression") != std::string::npos) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "powershell-invoke-expression",
                                    22,
                                    "Matched string: invoke-expression");
        }
        if (normalizedSample.find("frombase64string") != std::string::npos) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "powershell-base64-decoder",
                                    18,
                                    "Matched string: frombase64string");
        }
        if (normalizedSample.find("wscript.shell") != std::string::npos) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "script-shell-automation",
                                    18,
                                    "Matched string: wscript.shell");
        }
        if (normalizedSample.find("activexobject") != std::string::npos) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "activex-automation-object",
                                    15,
                                    "Matched string: activexobject");
        }
        if (normalizedSample.find("xmlhttp") != std::string::npos) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "scripted-web-request",
                                    15,
                                    "Matched string: xmlhttp");
        }
        if (normalizedSample.find("cmd.exe /c") != std::string::npos) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "command-shell-trampoline",
                                    20,
                                    "Matched execution syntax: cmd.exe /c");
        }
        if (normalizedSample.find("/bin/sh -c") != std::string::npos) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "shell-trampoline",
                                    20,
                                    "Matched execution syntax: /bin/sh -c");
        }
        if (normalizedSample.find("curl | sh") != std::string::npos) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "pipe-to-shell",
                                    30,
                                    "Matched execution syntax: curl | sh");
        }
        if (normalizedSample.find("wget | sh") != std::string::npos) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "pipe-to-shell",
                                    30,
                                    "Matched execution syntax: wget | sh");
        }

        const std::optional<std::string> remoteUrl = firstMatch(normalizedSample, {"https://", "http://"});

        if (normalizedSample.find("mshta") != std::string::npos) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "lolbin-mshta",
                                    15,
                                    "Matched string: mshta");
        }
        if (normalizedSample.find("regsvr32") != std::string::npos) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "lolbin-regsvr32",
                                    15,
                                    "Matched string: regsvr32");
        }
        if (normalizedSample.find("rundll32") != std::string::npos) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "lolbin-rundll32",
                                    15,
                                    "Matched string: rundll32");
        }
        if (normalizedSample.find("powershell") != std::string::npos &&
            std::find(triggeredRules.begin(), triggeredRules.end(), "powershell-encoded-command") == triggeredRules.end()) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "lolbin-powershell",
                                    15,
                                    "Matched string: powershell");
        } else if (normalizedSample.find("pwsh") != std::string::npos) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "lolbin-powershell",
                                    15,
                                    "Matched string: pwsh");
        }

        if (remoteUrl.has_value() && executionScore > 0) {
            appendWeightedIndicator(triggeredRules,
                                    evidence,
                                    executionScore,
                                    "remote-url-reference",
                                    20,
                                    "Matched remote URL scheme: " + *remoteUrl);
        }

        if (executionScore > 0) {
            evidence.insert(evidence.end(), contextualEvidence.begin(), contextualEvidence.end());
            const int adjustedScore = std::max(1, executionScore - scoreReduction);
            const double confidence = confidenceFromScore(adjustedScore);
            std::ostringstream summary;
            summary << "Weighted heuristic score " << adjustedScore << " from " << triggeredRules.size()
                    << " indicator(s). Standalone LOLBin references are treated as supporting evidence, not a full detection.";
            if (traits.sourceCode) {
                summary << " Source-code context lowers confidence unless additional indicators corroborate execution behavior.";
            }
            if (scoreReduction > 0) {
                summary << " Contextual reductions lowered the score by " << scoreReduction << '.';
            }

            result.findings.push_back(makeFinding(
                filePath,
                sha256,
                executionFindingName(triggeredRules),
                "The file contains a combination of execution, LOLBin, download, or script indicators associated with loader behavior.",
                summary.str(),
                "Review the file contents before execution. Quarantine the file if the combined indicators are unexpected or untrusted.",
                classificationFromConfidence(confidence),
                applyConfidenceSeverityCap(executionSeverityFromScore(adjustedScore), confidence),
                confidence,
                result.entropy,
                resolvedFileSize,
                triggeredRules,
                evidence
            ));
        }
    }

    if (traits.looksExecutable) {
        std::vector<std::string> packerEvidence;
        std::vector<std::string> triggeredRules = {"known-packer-signature"};
        int rawPackerScore = 0;
        int corroboratedSignals = 0;

        const bool hasUpx0 = normalizedSample.find("upx0") != std::string::npos;
        const bool hasUpx1 = normalizedSample.find("upx1") != std::string::npos;
        const bool hasUpxBang = normalizedSample.find("upx!") != std::string::npos;
        if (hasUpx0) {
            appendUnique(packerEvidence, "Matched section: UPX0");
        }
        if (hasUpx1) {
            appendUnique(packerEvidence, "Matched section: UPX1");
        }
        if (hasUpxBang) {
            appendUnique(packerEvidence, "Matched string: UPX!");
        }
        const int upxMarkerCount = static_cast<int>(hasUpx0) + static_cast<int>(hasUpx1) + static_cast<int>(hasUpxBang);

        const bool hasEntropySupport = result.entropy >= executableEntropyThreshold(traits);
        const bool hasEntryPointSupport = hasPeEntryPointAnomaly(sample, resolvedFileSize, packerEvidence);

        const bool hasMpressSectionMarker =
            containsWithinPrefix(normalizedSample, "mpress1", 8192) ||
            containsWithinPrefix(normalizedSample, "mpress2", 8192);
        if (hasMpressSectionMarker) {
            appendUnique(packerEvidence, "Matched section: MPRESS");
        }

        bool hasMpressStructuralMarker = false;
        if (normalizedSample.find("mpress") != std::string::npos) {
            const std::vector<unsigned char> tailSample = resolvedFileSize == 0
                ? std::vector<unsigned char> {}
                : readFileTail(filePath, resolvedFileSize, kTailBytes, errorMessage);
            if (!errorMessage.empty()) {
                result.error = errorMessage;
                return result;
            }
            hasMpressStructuralMarker = hasMpressMarkerNearStructure(sample, tailSample, resolvedFileSize, packerEvidence);
        }

        const bool hasAspackSectionMarker =
            containsWithinPrefix(normalizedSample, ".aspack", 8192) ||
            containsWithinPrefix(normalizedSample, "aspack", 1024);
        if (hasAspackSectionMarker) {
            appendUnique(packerEvidence, "Matched header or section marker: ASPACK");
        }

        if (upxMarkerCount >= 2) {
            appendUnique(triggeredRules, "packer-upx");
            corroboratedSignals = std::max(corroboratedSignals, upxMarkerCount + static_cast<int>(hasEntropySupport) + static_cast<int>(hasEntryPointSupport));
            rawPackerScore = std::max(rawPackerScore, 62 + ((upxMarkerCount - 2) * 6) + (hasEntropySupport ? 8 : 0) + (hasEntryPointSupport ? 6 : 0));
        } else if (upxMarkerCount == 1 && (hasEntropySupport || hasEntryPointSupport)) {
            appendUnique(triggeredRules, "packer-upx");
            corroboratedSignals = std::max(corroboratedSignals, 1 + static_cast<int>(hasEntropySupport) + static_cast<int>(hasEntryPointSupport));
            rawPackerScore = std::max(rawPackerScore, 42 + (hasEntropySupport ? 8 : 0) + (hasEntryPointSupport ? 6 : 0));
        }

        if (hasMpressStructuralMarker && (hasEntropySupport || hasMpressSectionMarker || hasEntryPointSupport)) {
            appendUnique(triggeredRules, "packer-mpress");
            corroboratedSignals = std::max(
                corroboratedSignals,
                1 + static_cast<int>(hasMpressSectionMarker) + static_cast<int>(hasEntropySupport) + static_cast<int>(hasEntryPointSupport)
            );
            rawPackerScore = std::max(
                rawPackerScore,
                54 + (hasMpressSectionMarker ? 10 : 0) + (hasEntropySupport ? 8 : 0) + (hasEntryPointSupport ? 6 : 0)
            );
        }

        if (hasAspackSectionMarker && (hasEntropySupport || hasEntryPointSupport)) {
            appendUnique(triggeredRules, "packer-aspack");
            corroboratedSignals = std::max(
                corroboratedSignals,
                1 + static_cast<int>(hasEntropySupport) + static_cast<int>(hasEntryPointSupport)
            );
            rawPackerScore = std::max(
                rawPackerScore,
                50 + (hasEntropySupport ? 8 : 0) + (hasEntryPointSupport ? 6 : 0)
            );
        }

        if (rawPackerScore > 0) {
            const int adjustedScore = std::max(1, rawPackerScore - scoreReduction);
            const double confidence = confidenceFromScore(adjustedScore);
            appendUnique(packerEvidence, "Entropy: " + formatEntropy(result.entropy));
            packerEvidence.insert(packerEvidence.end(), contextualEvidence.begin(), contextualEvidence.end());

            std::ostringstream summary;
            summary << "Known packer signature score " << adjustedScore << " based on " << corroboratedSignals
                    << " corroborated indicator(s). Standalone MPRESS or ASPACK strings are ignored unless supported by structure, section markers, or entropy.";
            if (scoreReduction > 0) {
                summary << " Contextual reductions lowered the score by " << scoreReduction << '.';
            }

            result.findings.push_back(makeFinding(
                filePath,
                sha256,
                "Known Packer Signature",
                "The file looks like an executable with corroborated packer indicators. This is suspicious, but not a standalone malware verdict.",
                summary.str(),
                "Submit the file for deeper analysis if the packer usage is unexpected in this environment.",
                classificationFromConfidence(confidence),
                applyConfidenceSeverityCap(packerSeverityFromScore(adjustedScore), confidence),
                confidence,
                result.entropy,
                resolvedFileSize,
                triggeredRules,
                packerEvidence
            ));
        }

        if (result.entropy >= executableEntropyThreshold(traits)) {
            const double entropyThreshold = executableEntropyThreshold(traits);
            const int rawScore = std::clamp(
                30 + static_cast<int>(std::round((result.entropy - entropyThreshold) * 18.0)),
                30,
                50
            );
            const int adjustedScore = std::max(1, rawScore - scoreReduction);
            const double confidence = confidenceFromScore(adjustedScore);
            std::vector<std::string> evidence = {
                "Entropy: " + formatEntropy(result.entropy)
            };
            evidence.insert(evidence.end(), contextualEvidence.begin(), contextualEvidence.end());

            std::ostringstream summary;
            summary << "High entropy score " << adjustedScore
                    << ". Entropy alone is treated as a weak-to-medium indicator for executable content.";
            if (scoreReduction > 0) {
                summary << " Contextual reductions lowered the score by " << scoreReduction << '.';
            }

            result.findings.push_back(makeFinding(
                filePath,
                sha256,
                "High Entropy Executable",
                "The file looks like an executable with unusually high entropy, which can indicate packing or obfuscation without proving malicious behavior.",
                summary.str(),
                "Inspect the executable lineage and signer information before treating it as malicious.",
                classificationFromConfidence(confidence),
                applyConfidenceSeverityCap(executableEntropySeverityFromScore(adjustedScore), confidence),
                confidence,
                result.entropy,
                resolvedFileSize,
                {"high-entropy-executable"},
                evidence
            ));
        }
    }

    if (traits.looksScript && result.entropy >= 6.80) {
        const int rawScore = std::clamp(35 + static_cast<int>(std::round((result.entropy - 6.80) * 12.0)), 35, 48);
        const int adjustedScore = std::max(1, rawScore - scoreReduction);
        const double confidence = confidenceFromScore(adjustedScore);
        std::vector<std::string> evidence = {
            "Entropy: " + formatEntropy(result.entropy)
        };
        evidence.insert(evidence.end(), contextualEvidence.begin(), contextualEvidence.end());

        std::ostringstream summary;
        summary << "High entropy script score " << adjustedScore
                << ". Script entropy is treated as a finding unless other suspicious indicators are present.";
        if (scoreReduction > 0) {
            summary << " Contextual reductions lowered the score by " << scoreReduction << '.';
        }

        result.findings.push_back(makeFinding(
            filePath,
            sha256,
            "High Entropy Script Content",
            "The file looks like a script but contains highly entropic content, which can indicate obfuscation or bundled payload material.",
            summary.str(),
            "Review the script for encoded or obfuscated content before execution.",
            classificationFromConfidence(confidence),
            applyConfidenceSeverityCap(executableEntropySeverityFromScore(adjustedScore), confidence),
            confidence,
            result.entropy,
            resolvedFileSize,
            {"high-entropy-script"},
            evidence
        ));
    }

    return result;
}

} // namespace warden::scanner
