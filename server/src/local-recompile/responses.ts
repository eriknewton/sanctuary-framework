/**
 * The only responses the local task tool returns. Each is one text item of
 * compact JSON with a fixed key order and is never an error result, so every
 * accepted call reads the same whatever later happens to its job. Must match
 * the test-local copies in test/local-recompile/tool-responses.test.ts.
 */
export const LOCAL_TASK_TOOL_NAME = "sanctuary_local_task";

/** Must match the description pinned in test/local-recompile/tool-responses.test.ts. */
export const LOCAL_TASK_DESCRIPTION =
  "Hands a summary task over records stored in Sanctuary to the local model on this machine. " +
  "The summary is shown only to the user, in the Sanctuary dashboard, and is never returned to you. " +
  "Every accepted request gets the same acknowledgement, whether or not it later succeeds. " +
  "No hosted model is called. Tell the user the summary will appear in their dashboard.";

export const LOCAL_TASK_SUBMITTED_NOTE = "Submitted. Any result appears only in the user's Sanctuary dashboard.";

export interface LocalTaskResponse {
  content: Array<{ type: "text"; text: string }>;
}

function response(text: string): LocalTaskResponse {
  return { content: [{ type: "text", text }] };
}

/** A1: the acknowledgement for every accepted call; the id is the only varying field and has a fixed length. */
export function submittedResponse(requestId: string): LocalTaskResponse {
  return response(JSON.stringify({ status: "submitted", request_id: requestId, note: LOCAL_TASK_SUBMITTED_NOTE }));
}

/** A2: the handler's strict check refused the input. */
export const INVALID_INPUT_TEXT = '{"status":"invalid_input"}';
/** A3: the tool is disarmed or the submission row could not be made durable. */
export const UNAVAILABLE_TEXT = '{"status":"unavailable"}';
/** A5: the seat is over its submission rate. */
export const BUSY_TEXT = '{"status":"busy"}';

export function invalidInputResponse(): LocalTaskResponse {
  return response(INVALID_INPUT_TEXT);
}

export function unavailableResponse(): LocalTaskResponse {
  return response(UNAVAILABLE_TEXT);
}

export function busyResponse(): LocalTaskResponse {
  return response(BUSY_TEXT);
}
