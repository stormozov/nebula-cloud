import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  getTokenExpirationTime,
  isTokenExpired,
} from "@/shared/utils/isTokenExpired";

/**
 * @fileoverview Unit tests for JWT token expiration utilities.
 * Ensures 100% coverage of getTokenExpirationTime and isTokenExpired functions.
 * Tests pure functions in isolation with mocked Date.now for determinism.
 */

describe("getTokenExpirationTime", () => {
  /**
   * @description Should parse valid JWT with exp claim and return milliseconds
   * @scenario Valid JWT token with exp=1710000000 (future) is parsed
   * @expected Returns 1710000000000 (exp * 1000)
   */
  it("should return exp time in ms for valid JWT with exp", () => {
    const token =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAwMDAwMDB9.signature";
    const result = getTokenExpirationTime(token);
    expect(result).toBe(1710000000000);
  });

  /**
   * @description Should return null for valid JWT without exp claim
   * @scenario JWT payload lacks exp field
   * @expected Returns null
   */
  it("should return null for valid JWT without exp", () => {
    const token =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature";
    const result = getTokenExpirationTime(token);
    expect(result).toBeNull();
  });

  /**
   * @description Should return null for malformed token (invalid base64)
   * @scenario Token payload part is not valid base64 → atob throws
   * @expected Returns null (catch block)
   */
  it("should return null for malformed token (invalid base64)", () => {
    const token = "header.invalidpayload.signature";
    const result = getTokenExpirationTime(token);
    expect(result).toBeNull();
  });

  /**
   * @description Should return null for token with no payload (short format)
   * @scenario Token.split('.')[1] is undefined → JSON.parse throws
   * @expected Returns null (catch block)
   */
  it("should return null for token missing payload", () => {
    const token = "header.signature";
    const result = getTokenExpirationTime(token);
    expect(result).toBeNull();
  });

  /**
   * @description Should return null for empty token string
   * @scenario Empty string → split yields no payload → throws
   * @expected Returns null (catch block)
   */
  it("should return null for empty token", () => {
    const result = getTokenExpirationTime("");
    expect(result).toBeNull();
  });
});

describe("isTokenExpired", () => {
  let mockNow: number;

  beforeEach(() => {
    vi.clearAllMocks();
    mockNow = 1700000000000; // Fixed timestamp for determinism
    vi.spyOn(Date, "now").mockImplementation(
      () => mockNow as unknown as number,
    );
  });

  /**
   * @description Should return true for null token
   * @scenario Token is explicitly null
   * @expected Returns true (early return)
   */
  it("should return true for null token", () => {
    const result = isTokenExpired(null);
    expect(result).toBe(true);
  });

  /**
   * @description Should return true for empty string token
   * @scenario Falsy token string
   * @expected Returns true (early return)
   */
  it("should return true for empty string token", () => {
    const result = isTokenExpired("");
    expect(result).toBe(true);
  });

  /**
   * @description Should return true for invalid token (no exp)
   * @scenario Valid JWT but getTokenExpirationTime returns null
   * @expected Returns true (no exp check)
   */
  it("should return true for invalid token without exp", () => {
    const token =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature";
    const result = isTokenExpired(token);
    expect(result).toBe(true);
  });

  /**
   * @description Should return true for expired token
   * @scenario Token exp=1690000000 (past relative to mockNow), now >= exp
   * @expected Returns true
   */
  it("should return true for expired token", () => {
    const token =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2OTAwMDAwMDB9.signature";
    mockNow = 1700000000000; // > exp*1000 = 1690000000000
    vi.spyOn(Date, "now").mockImplementation(
      () => mockNow as unknown as number,
    );
    const result = isTokenExpired(token);

    expect(result).toBe(true);
  });

  /**
   * @description Should return false for valid non-expired token
   * @scenario Token exp=1710000000 (future relative to mockNow), now < exp
   * @expected Returns false
   */
  it("should return false for non-expired token", () => {
    const token =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAwMDAwMDB9.signature";
    mockNow = 1709000000000; // < exp*1000 = 1710000000000
    vi.spyOn(Date, "now").mockImplementation(
      () => mockNow as unknown as number,
    );
    const result = isTokenExpired(token);

    expect(result).toBe(false);
  });

  /**
   * @description Should return true for malformed token
   * @scenario Malformed token → getTokenExpirationTime null
   * @expected Returns true (no exp check)
   */
  it("should return true for malformed token", () => {
    const token =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalidpayload.signature";
    const result = isTokenExpired(token);
    expect(result).toBe(true);
  });
});
