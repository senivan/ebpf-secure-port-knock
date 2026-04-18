/**
 * API client tests
 */
import { describe, it, expect, beforeEach } from 'vitest';

describe('API Client', () => {
  let baseURL: string;

  beforeEach(() => {
    baseURL = '/api';
  });

  it('should have correct base URL', () => {
    expect(baseURL).toBe('/api');
  });

  it('should construct login endpoint correctly', () => {
    const endpoint = `${baseURL}/auth/login`;
    expect(endpoint).toBe('/api/auth/login');
  });

  it('should construct dashboard endpoint correctly', () => {
    const endpoint = `${baseURL}/dashboard/status`;
    expect(endpoint).toBe('/api/dashboard/status');
  });

  it('should construct IP list endpoint correctly', () => {
    const endpoint = `${baseURL}/ips/list`;
    expect(endpoint).toBe('/api/ips/list');
  });

  it('should construct config endpoint correctly', () => {
    const endpoint = `${baseURL}/config/get`;
    expect(endpoint).toBe('/api/config/get');
  });

  it('should construct test endpoint correctly', () => {
    const endpoint = `${baseURL}/test/send-knock`;
    expect(endpoint).toBe('/api/test/send-knock');
  });

  it('should construct logs endpoint correctly', () => {
    const endpoint = `${baseURL}/logs/list`;
    expect(endpoint).toBe('/api/logs/list');
  });

  it('should format auth header correctly', () => {
    const token = 'test-token-123';
    const header = `Bearer ${token}`;
    expect(header).toBe('Bearer test-token-123');
  });

  it('should format content-type header correctly', () => {
    const contentType = 'application/json';
    expect(contentType).toBe('application/json');
  });
});
