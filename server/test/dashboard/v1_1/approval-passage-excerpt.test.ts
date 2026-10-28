import { describe, expect, it } from 'vitest';
import { runInNewContext } from 'node:vm';
import { getClientScript } from '../../../src/dashboard/v1_1/client.js';

function render(text: string, truncated = false, operation = 'memory_insert'): string {
  const script = getClientScript();
  const helpers = script.slice(script.indexOf('function escHtml('), script.indexOf('function escCssAttr('));
  const start = script.indexOf('function approvalPreviewHtml(');
  const preview = script.slice(start, script.indexOf('\n}\n', start) + 3);
  return runInNewContext(helpers + '\n' + preview + '\napprovalPreviewHtml(item)', {
    approvalHeldOperation: () => operation,
    item: { operator_preview: [
      { kind: 'byte_count', field: 'memory', value: Buffer.byteLength(text) },
      { kind: 'item_count', field: 'tags', value: 2 },
      { kind: 'passage_excerpt', field: 'memory', value: text, truncated },
    ] },
  });
}

describe('operator memory passage rendering', () => {
  it('renders script, image handlers and javascript links only as inert held-subject text with line breaks', () => {
    const text = '<script>alert(1)</script>\n<img onerror="alert(2)" src=x>\n<a href="javascript:alert(3)">link</a>\n[link](javascript:alert(4))';
    const html = render(text);
    expect(html).toContain('Save a memory: ' + Buffer.byteLength(text) + ' bytes, 2 tags');
    expect(html).toContain('<blockquote class="approval-passage">');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).toContain('&lt;img onerror=');
    expect(html).toContain('javascript:alert(3)');
    expect(html).toContain('[link](javascript:alert(4))');
    expect(html).not.toMatch(/<(?:script|img|a)\b/i);
    expect(html.match(/<br>/g)).toHaveLength(3);
    expect(html).not.toContain('(cut to');
  });
  it('shows the truncation notice and defensively bounds the excerpt without splitting a code point', () => {
    const html = render('a'.repeat(599) + '😀' + 'tail', true);
    expect(html).toContain('(cut to the first 600 characters)');
    expect(html).toContain('a'.repeat(599));
    expect(html).not.toContain('😀');
    expect(html).not.toContain('tail');
    expect(html).not.toContain('\\ud83d');
    expect(render('private', false, 'state_export')).not.toContain('private');
  });
});
