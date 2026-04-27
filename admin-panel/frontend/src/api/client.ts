import axios from 'axios';

const API_BASE_URL = '/api';

class ApiClient {
  private baseURL = API_BASE_URL;
  private token: string | null = null;

  setToken(token: string) {
    this.token = token;
  }

  getToken(): string | null {
    return this.token;
  }

  private getHeaders() {
    const headers: any = {
      'Content-Type': 'application/json',
    };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    return headers;
  }

  async login(username: string, password: string) {
    try {
      const response = await axios.post(
        `${this.baseURL}/auth/login`,
        { username, password }
      );
      return response.data;
    } catch (error) {
      throw error;
    }
  }

  async verifyToken() {
    try {
      const response = await axios.get(
        `${this.baseURL}/auth/verify`,
        { headers: this.getHeaders() }
      );
      return response.data;
    } catch (error) {
      throw error;
    }
  }

  // Dashboard endpoints
  async getSystemStatus() {
    const response = await axios.get(
      `${this.baseURL}/dashboard/status`,
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  async getStats() {
    const response = await axios.get(
      `${this.baseURL}/dashboard/stats`,
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  // Daemon endpoints
  async getDaemonStatus() {
    const response = await axios.get(
      `${this.baseURL}/daemon/status`,
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  async startDaemon(config?: any) {
    const response = await axios.post(
      `${this.baseURL}/daemon/start`,
      config || {},
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  async stopDaemon() {
    const response = await axios.post(
      `${this.baseURL}/daemon/stop`,
      {},
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  async restartDaemon(config?: any) {
    const response = await axios.post(
      `${this.baseURL}/daemon/restart`,
      config || {},
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  // Config endpoints
  async getConfig() {
    const response = await axios.get(
      `${this.baseURL}/config/get`,
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  async updateConfig(config: any) {
    const response = await axios.post(
      `${this.baseURL}/config/update`,
      config,
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  async getHmacKey() {
    const response = await axios.get(
      `${this.baseURL}/config/keys/hmac`,
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  async updateHmacKey(hmacKey: string) {
    const response = await axios.post(
      `${this.baseURL}/config/keys/hmac/update`,
      { hmac_key: hmacKey },
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  // Auth IPs endpoints
  async getAuthorizedIps() {
    const response = await axios.get(
      `${this.baseURL}/auth-ips/list`,
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  async authorizeIp(ip: string, durationMs: number = 5000) {
    const response = await axios.post(
      `${this.baseURL}/auth-ips/authorize`,
      { ip, duration_ms: durationMs },
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  async revokeIp(ip: string) {
    const response = await axios.post(
      `${this.baseURL}/auth-ips/revoke`,
      { ip },
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  async revokeAllIps() {
    const response = await axios.post(
      `${this.baseURL}/auth-ips/revoke-all`,
      {},
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  // Logs endpoints
  async getEvents(limit = 100, severity?: string) {
    const params: any = { limit };
    if (severity) params.severity = severity;
    const response = await axios.get(
      `${this.baseURL}/logs/events`,
      { headers: this.getHeaders(), params }
    );
    return response.data;
  }

  async getSystemLogs(lines = 50) {
    const response = await axios.get(
      `${this.baseURL}/logs/system-logs`,
      { headers: this.getHeaders(), params: { lines } }
    );
    return response.data;
  }

  // Test endpoints
  async sendKnockPacket(srcIp: string, dstIp: string, hmacKey: string, dstPort = 40000, ifname = 'eth0') {
    const response = await axios.post(
      `${this.baseURL}/test/knock-packet`,
      { src_ip: srcIp, dst_ip: dstIp, hmac_key: hmacKey, dst_port: dstPort, ifname },
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  async testConnectivity(target: string, port = 22) {
    const response = await axios.post(
      `${this.baseURL}/test/connectivity`,
      { target, port },
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  async testConfigReload() {
    const response = await axios.post(
      `${this.baseURL}/test/config-reload`,
      {},
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  async testMapsIntegrity() {
    const response = await axios.get(
      `${this.baseURL}/test/maps-integrity`,
      { headers: this.getHeaders() }
    );
    return response.data;
  }

  async testSystemHealth() {
    const response = await axios.get(
      `${this.baseURL}/test/system-health`,
      { headers: this.getHeaders() }
    );
    return response.data;
  }
}

export default new ApiClient();
