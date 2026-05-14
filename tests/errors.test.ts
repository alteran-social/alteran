/**
 * Error Handling Tests
 * Tests for XRPC error hierarchy and error handling
 */

import { describe, test, expect } from 'bun:test';

describe('Error Handling', () => {
  describe('XRPCError Base Class', () => {
    test('should create error with code, message, and status', async () => {
      const { XRPCError } = await import('../src/lib/errors');

      const error = new XRPCError('TestError', 'Test message', 400);

      expect(error.code).toBe('TestError');
      expect(error.message).toBe('Test message');
      expect(error.status).toBe(400);
      expect(error.name).toBe('XRPCError');
    });

    test('should serialize to JSON', async () => {
      const { XRPCError } = await import('../src/lib/errors');

      const error = new XRPCError('TestError', 'Test message', 400, { extra: 'data' });
      const json = error.toJSON();

      expect(json).toEqual({
        error: 'TestError',
        message: 'Test message',
        details: { extra: 'data' },
      });
    });

    test('should convert to Response', async () => {
      const { XRPCError } = await import('../src/lib/errors');

      const error = new XRPCError('TestError', 'Test message', 400);
      const response = error.toResponse('test-request-id');

      expect(response.status).toBe(400);
      expect(response.headers.get('Content-Type')).toBe('application/json');
      expect(response.headers.get('X-Request-ID')).toBe('test-request-id');

      const body = (await response.json()) as { error: string; message: string };
      expect(body.error).toBe('TestError');
      expect(body.message).toBe('Test message');
    });
  });

  describe('Error Subclasses', () => {
    test('InvalidRequest should have 400 status', async () => {
      const { InvalidRequest } = await import('../src/lib/errors');

      const error = new InvalidRequest('Bad input');

      expect(error.code).toBe('InvalidRequest');
      expect(error.status).toBe(400);
      expect(error.message).toBe('Bad input');
    });

    test('AuthRequired should have 401 status', async () => {
      const { AuthRequired } = await import('../src/lib/errors');

      const error = new AuthRequired();

      expect(error.code).toBe('AuthRequired');
      expect(error.status).toBe(401);
      expect(error.message).toBe('Authentication required');
    });

    test('InvalidToken should have 401 status', async () => {
      const { InvalidToken } = await import('../src/lib/errors');

      const error = new InvalidToken();

      expect(error.code).toBe('InvalidToken');
      expect(error.status).toBe(401);
      expect(error.message).toBe('Invalid or expired token');
    });

    test('Forbidden should have 403 status', async () => {
      const { Forbidden } = await import('../src/lib/errors');

      const error = new Forbidden();

      expect(error.code).toBe('Forbidden');
      expect(error.status).toBe(403);
      expect(error.message).toBe('Access forbidden');
    });

    test('NotFound should have 404 status', async () => {
      const { NotFound } = await import('../src/lib/errors');

      const error = new NotFound('Resource not found');

      expect(error.code).toBe('NotFound');
      expect(error.status).toBe(404);
      expect(error.message).toBe('Resource not found');
    });

    test('RateLimitExceeded should have 429 status', async () => {
      const { RateLimitExceeded } = await import('../src/lib/errors');

      const error = new RateLimitExceeded();

      expect(error.code).toBe('RateLimitExceeded');
      expect(error.status).toBe(429);
      expect(error.message).toBe('Rate limit exceeded');
    });

    test('InternalServerError should have 500 status', async () => {
      const { InternalServerError } = await import('../src/lib/errors');

      const error = new InternalServerError();

      expect(error.code).toBe('InternalServerError');
      expect(error.status).toBe(500);
      expect(error.message).toBe('Internal server error');
    });
  });

  describe('User-Friendly Messages', () => {
    test('should provide actionable messages', async () => {
      const { getUserFriendlyMessage } = await import('../src/lib/errors');

      expect(getUserFriendlyMessage('AuthRequired')).toBe('Please log in to continue.');
      expect(getUserFriendlyMessage('InvalidToken')).toBe('Your session has expired. Please log in again.');
      expect(getUserFriendlyMessage('RateLimitExceeded')).toBe('Too many requests. Please try again later.');
    });

    test('should have fallback message for unknown codes', async () => {
      const { getUserFriendlyMessage } = await import('../src/lib/errors');

      const message = getUserFriendlyMessage('UnknownError');
      expect(message).toBe('An error occurred. Please try again.');
    });
  });

  describe('Error Categorization', () => {
    test('should categorize 4xx as client errors', async () => {
      const { categorizeError } = await import('../src/lib/errors');

      expect(categorizeError(400)).toBe('client');
      expect(categorizeError(401)).toBe('client');
      expect(categorizeError(403)).toBe('client');
      expect(categorizeError(404)).toBe('client');
      expect(categorizeError(429)).toBe('client');
    });

    test('should categorize 5xx as server errors', async () => {
      const { categorizeError } = await import('../src/lib/errors');

      expect(categorizeError(500)).toBe('server');
      expect(categorizeError(502)).toBe('server');
      expect(categorizeError(503)).toBe('server');
    });

    test('should categorize 3xx as server errors', async () => {
      const { categorizeError } = await import('../src/lib/errors');

      expect(categorizeError(301)).toBe('server');
      expect(categorizeError(302)).toBe('server');
    });
  });

  describe('Error Conversion', () => {
    test('should convert XRPCError to XRPCError', async () => {
      const { toXRPCError, InvalidRequest } = await import('../src/lib/errors');

      const original = new InvalidRequest('Test');
      const converted = toXRPCError(original);

      expect(converted).toBe(original);
    });

    test('should convert Error to InternalServerError', async () => {
      const { toXRPCError } = await import('../src/lib/errors');

      const original = new Error('Something went wrong');
      const converted = toXRPCError(original);

      expect(converted.code).toBe('InternalServerError');
      expect(converted.message).toBe('Something went wrong');
      expect(converted.status).toBe(500);
    });

    test('should convert unknown to InternalServerError', async () => {
      const { toXRPCError } = await import('../src/lib/errors');

      const converted = toXRPCError('string error');

      expect(converted.code).toBe('InternalServerError');
      expect(converted.status).toBe(500);
    });

    test('should not expose stack details in converted public errors', async () => {
      const { toXRPCError } = await import('../src/lib/errors');

      const original = new Error('Test error');
      const converted = toXRPCError(original);

      expect(converted.details).toBeUndefined();
      const body = converted.toJSON();
      expect('details' in body).toBe(false);
    });
  });

  describe('Error Details', () => {
    test('should include optional details', async () => {
      const { NotFound } = await import('../src/lib/errors');

      const error = new NotFound('User not found', { userId: '123' });

      expect(error.details).toEqual({ userId: '123' });

      const json = error.toJSON();
      expect(json.details).toEqual({ userId: '123' });
    });

    test('should omit details if not provided', async () => {
      const { NotFound } = await import('../src/lib/errors');

      const error = new NotFound('User not found');

      expect(error.details).toBeUndefined();

      const json = error.toJSON();
      expect(json.details).toBeUndefined();
    });
  });

  describe('Error Response Headers', () => {
    test('should include Content-Type header', async () => {
      const { InvalidRequest } = await import('../src/lib/errors');

      const error = new InvalidRequest();
      const response = error.toResponse();

      expect(response.headers.get('Content-Type')).toBe('application/json');
    });

    test('should include request ID if provided', async () => {
      const { InvalidRequest } = await import('../src/lib/errors');

      const error = new InvalidRequest();
      const response = error.toResponse('req-123');

      expect(response.headers.get('X-Request-ID')).toBe('req-123');
    });

    test('should not include request ID if not provided', async () => {
      const { InvalidRequest } = await import('../src/lib/errors');

      const error = new InvalidRequest();
      const response = error.toResponse();

      expect(response.headers.get('X-Request-ID')).toBeNull();
    });
  });
});
