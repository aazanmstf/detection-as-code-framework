const resultBadge = document.getElementById("result-badge");
const runButton = document.getElementById("run-validation");
const statRules = document.getElementById("stat-rules");
const statScore = document.getElementById("stat-score");
const statTechniques = document.getElementById("stat-techniques");
const statUnmapped = document.getElementById("stat-unmapped");
const rulesBody = document.getElementById("rules-body");
const coverageBody = document.getElementById("coverage-body");
const issuesPanel = document.getElementById("issues-panel");
const issuesList = document.getElementById("issues-list");

function setBadge(result) {
  resultBadge.textContent = result;
  resultBadge.className =
    "badge " + (result === "PASS" ? "badge-pass" : result === "FAIL" ? "badge-fail" : "badge-pending");
}

function scoreClass(score) {
  if (score >= 90) return "score-high";
  if (score >= 70) return "score-mid";
  return "score-low";
}

function renderRules(rules) {
  if (!rules.length) {
    rulesBody.innerHTML = '<tr><td colspan="5" class="empty-row">No rules found in detections/</td></tr>';
    return;
  }

  rulesBody.innerHTML = rules
    .map((rule) => {
      const statusClass = rule.passed ? "pass" : "fail";
      const statusLabel = rule.passed ? "PASS" : "FAIL";
      const techniques = rule.attack_techniques.length
        ? rule.attack_techniques.map((t) => `<span class="technique-tag">${t}</span>`).join("")
        : '<span class="file-path">none</span>';

      return `
        <tr>
          <td><span class="status-dot ${statusClass}"></span>${statusLabel}</td>
          <td>${escapeHtml(rule.title)}</td>
          <td class="file-path">${escapeHtml(rule.path)}</td>
          <td>${techniques}</td>
          <td class="score-cell ${scoreClass(rule.score)}">${rule.score}/100</td>
        </tr>
      `;
    })
    .join("");
}

function renderCoverage(coverage) {
  if (!coverage.techniques.length) {
    coverageBody.innerHTML = '<tr><td colspan="3" class="empty-row">No ATT&CK techniques found</td></tr>';
    return;
  }

  coverageBody.innerHTML = coverage.techniques
    .map(
      (row) => `
        <tr>
          <td class="file-path">${escapeHtml(row.technique)}</td>
          <td>${escapeHtml(row.name)}</td>
          <td>${row.count}</td>
        </tr>
      `
    )
    .join("");
}

function renderIssues(rules, duplicateIds) {
  const allIssues = [];

  duplicateIds.forEach((message) => {
    allIssues.push({ file: "(repository)", severity: "error", message });
  });

  rules.forEach((rule) => {
    rule.issues.forEach((issue) => {
      allIssues.push({ file: rule.path, severity: issue.severity, message: issue.message });
    });
  });

  if (!allIssues.length) {
    issuesPanel.hidden = true;
    return;
  }

  issuesPanel.hidden = false;
  issuesList.innerHTML = allIssues
    .map(
      (issue) =>
        `<li class="issue-${issue.severity}"><strong>${escapeHtml(issue.file)}</strong>: ${escapeHtml(issue.message)}</li>`
    )
    .join("");
}

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value ?? "";
  return div.innerHTML;
}

async function loadReport(method = "GET") {
  runButton.disabled = true;
  runButton.textContent = "Running...";
  setBadge("...");

  try {
    const response = await fetch("/api/validate", { method });
    if (!response.ok) {
      throw new Error(`Server returned ${response.status}`);
    }
    const data = await response.json();

    if (data.error) {
      throw new Error(data.error);
    }

    setBadge(data.result);
    statRules.textContent = data.rules_discovered;
    statScore.textContent = `${data.average_score}/100`;
    statTechniques.textContent = data.coverage.unique_techniques;
    statUnmapped.textContent = data.coverage.unmapped_rules.length;

    renderRules(data.rules);
    renderCoverage(data.coverage);
    renderIssues(data.rules, data.duplicate_ids);
  } catch (err) {
    setBadge("ERROR");
    rulesBody.innerHTML = `<tr><td colspan="5" class="empty-row">Failed to load: ${escapeHtml(err.message)}</td></tr>`;
  } finally {
    runButton.disabled = false;
    runButton.textContent = "Run Validation";
  }
}

runButton.addEventListener("click", () => loadReport("POST"));

// Load automatically when the dashboard first opens.
loadReport("GET");
