import { describe, expect, it } from "vitest";
import {
  bytesToString,
  concatBytes,
  constantTimeEqual,
  fromBase64url,
  stringToBytes,
  toBase64url,
} from "../../../src/core/encoding.js";

function byteValues(bytes: Uint8Array): number[] {
  return Array.from(bytes);
}

describe("encoding utilities", () => {
  describe("toBase64url and fromBase64url", () => {
    it("round-trips an empty byte array", () => {
      const bytes = new Uint8Array();
      const encoded = toBase64url(bytes);

      expect(encoded).toBe("");
      expect(byteValues(fromBase64url(encoded))).toEqual([]);
    });

    it("round-trips bytes whose base64 encoding has no padding", () => {
      const bytes = Uint8Array.from([1, 2, 3]);
      const encoded = toBase64url(bytes);

      expect(encoded).toBe("AQID");
      expect(encoded).not.toContain("=");
      expect(byteValues(fromBase64url(encoded))).toEqual([1, 2, 3]);
    });

    it("uses URL-safe characters and strips padding for base64 containing plus and slash", () => {
      const bytes = Uint8Array.from([251, 255, 255]);
      const encoded = toBase64url(bytes);

      expect(Buffer.from(bytes).toString("base64")).toBe("+///");
      expect(encoded).toBe("-___");
      expect(encoded).not.toContain("+");
      expect(encoded).not.toContain("/");
      expect(encoded).not.toContain("=");
      expect(byteValues(fromBase64url(encoded))).toEqual([251, 255, 255]);
    });

    it("decodes a base64url string that needs one padding character restored", () => {
      const decoded = fromBase64url("AAA");

      expect(byteValues(decoded)).toEqual([0, 0]);
      expect(toBase64url(decoded)).toBe("AAA");
    });

    it("decodes a base64url string that needs two padding characters restored", () => {
      const decoded = fromBase64url("AA");

      expect(byteValues(decoded)).toEqual([0]);
      expect(toBase64url(decoded)).toBe("AA");
    });

    it("decodes a base64url string that needs no padding restored", () => {
      const decoded = fromBase64url("AAAA");

      expect(byteValues(decoded)).toEqual([0, 0, 0]);
      expect(toBase64url(decoded)).toBe("AAAA");
    });

    it("round-trips the full byte range", () => {
      const bytes = Uint8Array.from(
        { length: 256 },
        (_, index) => index
      );
      const encoded = toBase64url(bytes);
      const decoded = fromBase64url(encoded);

      expect(encoded).not.toContain("=");
      expect(decoded).toHaveLength(256);
      expect(byteValues(decoded)).toEqual(byteValues(bytes));
    });
  });

  describe("fromBase64url — lenient/non-canonical decoding (characterization)", () => {
    it("silently drops non-alphabet characters before decoding", () => {
      // Pins current lenient Buffer decoding behavior. Strict rejection would be
      // a separate src-level decision, out of scope for this characterization.
      expect(byteValues(fromBase64url("!!!!"))).toEqual([]);
      expect(byteValues(fromBase64url("AQID!@#"))).toEqual([1, 2, 3]);
    });

    it("decodes length%4==1 input using the current padding loop", () => {
      expect(byteValues(fromBase64url("A"))).toEqual([]);
    });

    it("allows non-canonical malleability for distinct strings with identical bytes", () => {
      const canonical = fromBase64url("AA");
      const nonCanonical = fromBase64url("AB");

      expect("AA").not.toBe("AB");
      expect(byteValues(canonical)).toEqual([0]);
      expect(byteValues(nonCanonical)).toEqual([0]);
      expect(byteValues(nonCanonical)).toEqual(byteValues(canonical));
    });
  });

  describe("stringToBytes and bytesToString", () => {
    it("round-trips ASCII strings", () => {
      const bytes = stringToBytes("Sanctuary MCP");

      expect(byteValues(bytes)).toEqual([
        83, 97, 110, 99, 116, 117, 97, 114, 121, 32, 77, 67, 80,
      ]);
      expect(bytes).toHaveLength(13);
      expect(bytesToString(bytes)).toBe("Sanctuary MCP");
    });

    it("round-trips an empty string", () => {
      const bytes = stringToBytes("");

      expect(byteValues(bytes)).toEqual([]);
      expect(bytes).toHaveLength(0);
      expect(bytesToString(bytes)).toBe("");
    });

    it("round-trips multibyte unicode with exact UTF-8 byte length", () => {
      const value = "é🚀";
      const bytes = stringToBytes(value);

      expect(byteValues(bytes)).toEqual([195, 169, 240, 159, 154, 128]);
      expect(bytes).toHaveLength(6);
      expect(bytesToString(bytes)).toBe(value);
    });

    it("replaces invalid UTF-8 bytes without throwing", () => {
      // Pins current TextDecoder behavior: malformed UTF-8 is lossy and emits
      // U+FFFD replacement characters instead of throwing.
      expect(bytesToString(Uint8Array.from([0xff]))).toBe("\uFFFD");
      expect(bytesToString(Uint8Array.from([0xed, 0xa0, 0x80]))).toBe(
        "\uFFFD\uFFFD\uFFFD"
      );
    });
  });

  describe("concatBytes", () => {
    it("returns an empty Uint8Array for zero arguments", () => {
      const concatenated = concatBytes();

      expect(concatenated).toBeInstanceOf(Uint8Array);
      expect(concatenated).toHaveLength(0);
      expect(byteValues(concatenated)).toEqual([]);
    });

    it("returns equal contents for a single array", () => {
      const concatenated = concatBytes(Uint8Array.from([7, 8, 9]));

      expect(concatenated).toHaveLength(3);
      expect(byteValues(concatenated)).toEqual([7, 8, 9]);
    });

    it("concatenates many arrays in order with the correct total length", () => {
      const concatenated = concatBytes(
        Uint8Array.from([1, 2]),
        Uint8Array.from([3]),
        Uint8Array.from([4, 5, 6])
      );

      expect(concatenated).toHaveLength(6);
      expect(byteValues(concatenated)).toEqual([1, 2, 3, 4, 5, 6]);
    });

    it("preserves order when arrays contain empties", () => {
      const concatenated = concatBytes(
        new Uint8Array(),
        Uint8Array.from([10]),
        new Uint8Array(),
        Uint8Array.from([11, 12])
      );

      expect(concatenated).toHaveLength(3);
      expect(byteValues(concatenated)).toEqual([10, 11, 12]);
    });
  });

  describe("constantTimeEqual", () => {
    // These assertions verify boolean correctness only, not the timing property.
    // Constant-time behavior is not unit-testable; this keeps the suite aligned
    // with the repo's no-wall-clock-gate rule.
    it("returns true for equal same-length arrays", () => {
      expect(
        constantTimeEqual(Uint8Array.from([1, 2, 3]), Uint8Array.from([1, 2, 3]))
      ).toBe(true);
    });

    it("returns false for unequal same-length arrays", () => {
      expect(
        constantTimeEqual(Uint8Array.from([1, 2, 3]), Uint8Array.from([1, 2, 4]))
      ).toBe(false);
    });

    it("returns false for different-length arrays", () => {
      expect(
        constantTimeEqual(Uint8Array.from([1, 2, 3]), Uint8Array.from([1, 2]))
      ).toBe(false);
    });

    it("returns true for two empty arrays", () => {
      expect(constantTimeEqual(new Uint8Array(), new Uint8Array())).toBe(true);
    });

    it("returns false when only the first byte differs", () => {
      expect(
        constantTimeEqual(
          Uint8Array.from([99, 2, 3, 4]),
          Uint8Array.from([1, 2, 3, 4])
        )
      ).toBe(false);
    });

    it("returns false when only the last byte differs", () => {
      expect(
        constantTimeEqual(
          Uint8Array.from([1, 2, 3, 99]),
          Uint8Array.from([1, 2, 3, 4])
        )
      ).toBe(false);
    });
  });
});
