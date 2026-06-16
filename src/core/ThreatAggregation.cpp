#include "warden/core/ThreatAggregation.h"

#include <algorithm>
#include <unordered_map>

namespace {

template<typename T>
void appendUnique(std::vector<T> &destination, const T &value)
{
    if (std::find(destination.begin(), destination.end(), value) == destination.end()) {
        destination.push_back(value);
    }
}

} // namespace

namespace warden::core {

std::string threatRecordId(const ThreatFinding &finding)
{
    if (!finding.sha256.empty()) {
        return finding.path.string() + "|" + finding.sha256;
    }

    return finding.path.string();
}

std::vector<ThreatRecord> aggregateThreatFindings(const std::vector<ThreatFinding> &findings)
{
    std::vector<ThreatRecord> records;
    std::unordered_map<std::string, std::size_t> indexById;

    for (const auto &finding : findings) {
        const std::string id = threatRecordId(finding);
        auto iterator = indexById.find(id);
        if (iterator == indexById.end()) {
            ThreatRecord record;
            record.id = id;
            record.name = finding.name;
            record.path = finding.path;
            record.threatType = finding.threatType;
            record.classification = finding.classification;
            record.severity = finding.severity;
            record.detectionSource = finding.detectionSource;
            record.description = finding.description;
            record.operatorSummary = finding.operatorSummary.empty() ? finding.description : finding.operatorSummary;
            record.recommendedAction = finding.recommendedAction;
            record.sha256 = finding.sha256;
            record.fileSize = finding.fileSize;
            record.entropy = finding.entropy;
            record.confidenceScore = finding.confidenceScore;
            record.findings.push_back(finding);
            if (!finding.detectionEngine.empty()) {
                record.detectionEngines.push_back(finding.detectionEngine);
            } else if (!finding.source.empty()) {
                record.detectionEngines.push_back(finding.source);
            }
            record.triggeredRules = finding.triggeredRules;
            record.evidence = finding.evidence;
            record.detectionMethod = toString(finding.detectionSource);
            indexById.emplace(id, records.size());
            records.push_back(std::move(record));
            continue;
        }

        ThreatRecord &record = records.at(iterator->second);
        record.findings.push_back(finding);
        if (static_cast<int>(finding.severity) > static_cast<int>(record.severity)) {
            record.severity = finding.severity;
            record.name = finding.name;
            record.description = finding.description;
            record.operatorSummary = finding.operatorSummary.empty() ? finding.description : finding.operatorSummary;
            record.recommendedAction = finding.recommendedAction;
            record.threatType = finding.threatType;
        }
        if (findingCategoryRank(finding.classification) > findingCategoryRank(record.classification)) {
            record.classification = finding.classification;
        }
        record.confidenceScore = std::max(record.confidenceScore, finding.confidenceScore);
        record.fileSize = std::max(record.fileSize, finding.fileSize);
        record.entropy = std::max(record.entropy, finding.entropy);
        if (record.sha256.empty()) {
            record.sha256 = finding.sha256;
        }

        const std::string engineLabel = !finding.detectionEngine.empty() ? finding.detectionEngine : finding.source;
        if (!engineLabel.empty()) {
            appendUnique(record.detectionEngines, engineLabel);
        }
        for (const auto &triggeredRule : finding.triggeredRules) {
            appendUnique(record.triggeredRules, triggeredRule);
        }
        for (const auto &evidenceLine : finding.evidence) {
            appendUnique(record.evidence, evidenceLine);
        }

        if (record.detectionSource != finding.detectionSource) {
            record.detectionSource = DetectionSource::Multiple;
        }
        record.detectionMethod = toString(record.detectionSource);
    }

    std::sort(records.begin(), records.end(), [](const ThreatRecord &left, const ThreatRecord &right) {
        if (left.path != right.path) {
            return left.path.string() < right.path.string();
        }
        return left.name < right.name;
    });

    return records;
}

} // namespace warden::core
