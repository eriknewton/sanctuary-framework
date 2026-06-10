// Best-effort upsert of a marker-keyed PR comment, used by synthetic-coverage.yml.
//
// PR comments are informational only: the job verdict must come from the
// coverage/gate evaluation steps, never from comment I/O. A GitHub API outage
// (e.g. the 2026-06-10 intermittent 401s) must not fail an otherwise-green job.
//
// Contract: NEVER throws. Retries transient API failures with short backoff,
// then logs a warning and gives up. Returns true if the comment landed.
module.exports = async function upsertPrComment({ github, context, core }, marker, body) {
  const maxAttempts = 3;
  const backoffMs = [2000, 5000];
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const { owner, repo } = context.repo;
      const issue_number = context.issue.number;
      const comments = await github.paginate(github.rest.issues.listComments, {
        owner,
        repo,
        issue_number,
      });
      const existing = comments.find((comment) => comment.body?.startsWith(marker));
      if (existing) {
        await github.rest.issues.updateComment({
          owner,
          repo,
          comment_id: existing.id,
          body,
        });
      } else {
        await github.rest.issues.createComment({
          owner,
          repo,
          issue_number,
          body,
        });
      }
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (attempt < maxAttempts) {
        core.warning(
          `PR comment ${marker}: attempt ${attempt}/${maxAttempts} failed (${message}); retrying in ${backoffMs[attempt - 1]}ms.`,
        );
        await new Promise((resolve) => setTimeout(resolve, backoffMs[attempt - 1]));
      } else {
        core.warning(
          `PR comment ${marker}: all ${maxAttempts} attempts failed (${message}). ` +
            "Giving up; the comment is informational and the job verdict is unaffected. " +
            "See the uploaded workflow artifact for the report.",
        );
      }
    }
  }
  return false;
};
