import * as grpc from '@grpc/grpc-js'
import * as protoLoader from '@grpc/proto-loader'
import path from 'path'

// Proto file paths
const PROTO_PATH = path.join(__dirname, '..', '..', 'services', 'proto')

// Load proto files
const commonProto = protoLoader.loadSync(
  path.join(PROTO_PATH, 'common.proto'),
  {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
  }
)

const osintProto = protoLoader.loadSync(
  path.join(PROTO_PATH, 'osint.proto'),
  {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
    includeDirs: [PROTO_PATH]
  }
)

const scannerProto = protoLoader.loadSync(
  path.join(PROTO_PATH, 'scanner.proto'),
  {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
    includeDirs: [PROTO_PATH]
  }
)

const packetProto = protoLoader.loadSync(
  path.join(PROTO_PATH, 'packet.proto'),
  {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
    includeDirs: [PROTO_PATH]
  }
)

const crawlerProto = protoLoader.loadSync(
  path.join(PROTO_PATH, 'crawler.proto'),
  {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
    includeDirs: [PROTO_PATH]
  }
)

// Load package definitions
const commonPackage = grpc.loadPackageDefinition(commonProto) as any
const osintPackage = grpc.loadPackageDefinition(osintProto) as any
const scannerPackage = grpc.loadPackageDefinition(scannerProto) as any
const packetPackage = grpc.loadPackageDefinition(packetProto) as any
const crawlerPackage = grpc.loadPackageDefinition(crawlerProto) as any

// Service URLs
const OSINT_URL = process.env.OSINT_SERVICE_URL || 'localhost:8001'
const SCANNER_URL = process.env.SCANNER_SERVICE_URL || 'localhost:8002'
const PACKET_URL = process.env.PACKET_SERVICE_URL || 'localhost:8003'
const CRAWLER_URL = process.env.CRAWLER_SERVICE_URL || 'localhost:8004'

export class GrpcClients {
  private osintClient: any
  private scannerClient: any
  private packetClient: any
  private crawlerClient: any
  
  constructor() {
    // Initialize clients
    this.osintClient = new osintPackage.cobra.osint.OSINTService(
      OSINT_URL,
      grpc.credentials.createInsecure()
    )
    
    this.scannerClient = new scannerPackage.cobra.scanner.PortScanner(
      SCANNER_URL,
      grpc.credentials.createInsecure()
    )
    
    this.packetClient = new packetPackage.cobra.packet.PacketManipulator(
      PACKET_URL,
      grpc.credentials.createInsecure()
    )
    
    this.crawlerClient = new crawlerPackage.cobra.crawler.WebCrawler(
      CRAWLER_URL,
      grpc.credentials.createInsecure()
    )
  }
  
  // OSINT Methods
  async gatherOSINT(target: string, tools: any, options?: any): Promise<any> {
    return new Promise((resolve, reject) => {
      this.osintClient.GatherOSINT({
        target,
        tools,
        options: options || {}
      }, (error: any, response: any) => {
        if (error) {
          reject(error)
        } else {
          resolve(response)
        }
      })
    })
  }
  
  // Scanner Methods
  async scanPorts(target: string, ports: number[], options?: any): Promise<any> {
    return new Promise((resolve, reject) => {
      this.scannerClient.ScanPorts({
        target,
        ports,
        timeout_ms: options?.timeout_ms || 1000,
        max_concurrent: options?.max_concurrent || 100,
        techniques: options?.techniques || {}
      }, (error: any, response: any) => {
        if (error) {
          reject(error)
        } else {
          resolve(response)
        }
      })
    })
  }
  
  streamScanPorts(target: string, ports: number[], options?: any): any {
    const call = this.scannerClient.StreamScanPorts({
      target,
      ports,
      timeout_ms: options?.timeout_ms || 1000,
      max_concurrent: options?.max_concurrent || 100,
      techniques: options?.techniques || {}
    })
    
    return call
  }
  
  // Packet Methods
  async craftPacket(request: any): Promise<any> {
    return new Promise((resolve, reject) => {
      this.packetClient.CraftPacket(request, (error: any, response: any) => {
        if (error) {
          reject(error)
        } else {
          resolve(response)
        }
      })
    })
  }
  
  async analyzePacket(packetData: Buffer): Promise<any> {
    return new Promise((resolve, reject) => {
      this.packetClient.AnalyzePacket({
        packet_data: packetData
      }, (error: any, response: any) => {
        if (error) {
          reject(error)
        } else {
          resolve(response)
        }
      })
    })
  }
  
  capturePackets(request: any): any {
    const call = this.packetClient.CapturePackets(request)
    return call
  }
  
  // Crawler Methods
  crawlWebsite(url: string, options?: any): any {
    const call = this.crawlerClient.CrawlWebsite({
      url,
      options: options || {
        max_depth: 3,
        max_pages: 100,
        respect_robots_txt: true,
        concurrent_requests: 5
      }
    })
    
    return call
  }
  
  async extractData(url: string, selectors: any[], javascriptRendering = false): Promise<any> {
    return new Promise((resolve, reject) => {
      this.crawlerClient.ExtractData({
        url,
        selectors,
        javascript_rendering: javascriptRendering
      }, (error: any, response: any) => {
        if (error) {
          reject(error)
        } else {
          resolve(response)
        }
      })
    })
  }
  
  async takeScreenshot(url: string, options?: any): Promise<any> {
    return new Promise((resolve, reject) => {
      this.crawlerClient.TakeScreenshot({
        url,
        options: options || {
          width: 1920,
          height: 1080,
          full_page: false,
          format: 'png'
        }
      }, (error: any, response: any) => {
        if (error) {
          reject(error)
        } else {
          resolve(response)
        }
      })
    })
  }
  
  async findSubdomains(domain: string, sources?: string[]): Promise<any> {
    return new Promise((resolve, reject) => {
      this.crawlerClient.FindSubdomains({
        domain,
        sources: sources || ['crtsh', 'dnsdumpster']
      }, (error: any, response: any) => {
        if (error) {
          reject(error)
        } else {
          resolve(response)
        }
      })
    })
  }
  
  // Health checks for all services
  async checkHealth(): Promise<any> {
    const healthChecks = await Promise.allSettled([
      this.checkServiceHealth(this.osintClient, 'OSINT'),
      this.checkServiceHealth(this.scannerClient, 'Scanner'),
      this.checkServiceHealth(this.packetClient, 'Packet'),
      this.checkServiceHealth(this.crawlerClient, 'Crawler')
    ])
    
    return healthChecks.map((result, index) => {
      const serviceName = ['OSINT', 'Scanner', 'Packet', 'Crawler'][index]
      if (result.status === 'fulfilled') {
        return { service: serviceName, ...result.value }
      } else {
        return { service: serviceName, status: 'unhealthy', error: result.reason.message }
      }
    })
  }
  
  private checkServiceHealth(client: any, name: string): Promise<any> {
    return new Promise((resolve, reject) => {
      const deadline = new Date()
      deadline.setSeconds(deadline.getSeconds() + 5)
      
      client.HealthCheck({}, { deadline }, (error: any, response: any) => {
        if (error) {
          reject(error)
        } else {
          resolve(response)
        }
      })
    })
  }
}

// Export singleton instance
export const grpcClients = new GrpcClients() 