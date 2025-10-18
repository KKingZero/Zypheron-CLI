import { spawn, spawnSync } from 'child_process'
import path from 'path'

export type ExecutionMethod = 'NATIVE' | 'WSL' | 'DOCKER'

export interface RunToolOptions {
  args?: string[]
  input?: string
  timeoutMs?: number
  cwd?: string
  env?: Record<string, string>
}

export interface RunResult {
  ok: boolean
  code: number | null
  stdout: string
  stderr: string
  method: ExecutionMethod | 'UNKNOWN'
}

export class ToolRunner {
  private preferredMethod: ExecutionMethod | null

  constructor(preferredMethod?: ExecutionMethod) {
    this.preferredMethod = preferredMethod || null
  }

  detectNative(tool: string): boolean {
    try {
      const whichCmd = process.platform === 'win32' ? 'where' : 'which'
      const result = spawnSync(whichCmd, [tool], { stdio: 'pipe' })
      return result.status === 0
    } catch {
      return false
    }
  }

  detectWSL(): boolean {
    if (process.platform !== 'win32') return false
    try {
      const result = spawnSync('wsl.exe', ['-l', '-q'], { stdio: 'pipe' })
      if (result.status !== 0) return false
      const list = (result.stdout?.toString() || '').toLowerCase()
      return list.includes('kali') || list.includes('kali-linux')
    } catch {
      return false
    }
  }

  detectWSLTool(tool: string): boolean {
    if (process.platform !== 'win32') return false
    try {
      const result = spawnSync('wsl.exe', ['-d', 'kali-linux', '--', 'which', tool], { stdio: 'pipe' })
      return result.status === 0
    } catch {
      return false
    }
  }

  detectDocker(): boolean {
    try {
      const result = spawnSync('docker', ['--version'], { stdio: 'pipe' })
      return result.status === 0
    } catch {
      return false
    }
  }

  async run(tool: string, options: RunToolOptions = {}): Promise<RunResult> {
    const args = options.args || []
    const timeoutMs = options.timeoutMs ?? 5 * 60_000

    const method = this.chooseMethod(tool)
    if (!method) {
      return { ok: false, code: null, stdout: '', stderr: `No available execution method for ${tool}`, method: 'UNKNOWN' }
    }

    if (method === 'NATIVE') {
      return this.runNative(tool, args, options)
    }
    if (method === 'WSL') {
      return this.runWSL(tool, args, options)
    }
    return this.runDocker(tool, args, options, 'kalilinux/kali-rolling')
  }

  chooseMethod(tool: string): ExecutionMethod | null {
    // Respect preferred method when available
    if (this.preferredMethod) {
      if (this.preferredMethod === 'NATIVE' && this.detectNative(tool)) return 'NATIVE'
      if (this.preferredMethod === 'WSL' && this.detectWSL() && this.detectWSLTool(tool)) return 'WSL'
      if (this.preferredMethod === 'DOCKER' && this.detectDocker()) return 'DOCKER'
    }

    // Auto-detect best available
    if (this.detectNative(tool)) return 'NATIVE'
    if (this.detectWSL() && this.detectWSLTool(tool)) return 'WSL'
    if (this.detectDocker()) return 'DOCKER'
    return null
  }

  private runNative(tool: string, args: string[], options: RunToolOptions): Promise<RunResult> {
    return new Promise((resolve) => {
      const child = spawn(tool, args, {
        cwd: options.cwd || process.cwd(),
        env: { ...process.env, ...(options.env || {}) },
        shell: false,
      })
      let stdout = ''
      let stderr = ''
      const timer = options.timeoutMs ? setTimeout(() => child.kill('SIGKILL'), options.timeoutMs) : null

      child.stdout?.on('data', (d) => (stdout += d.toString()))
      child.stderr?.on('data', (d) => (stderr += d.toString()))

      if (options.input) {
        child.stdin?.write(options.input)
        child.stdin?.end()
      }

      child.on('close', (code) => {
        if (timer) clearTimeout(timer)
        resolve({ ok: code === 0, code, stdout, stderr, method: 'NATIVE' })
      })
      child.on('error', (err) => {
        if (timer) clearTimeout(timer)
        resolve({ ok: false, code: null, stdout, stderr: String(err), method: 'NATIVE' })
      })
    })
  }

  private runWSL(tool: string, args: string[], options: RunToolOptions): Promise<RunResult> {
    return new Promise((resolve) => {
      const wslArgs = ['-d', 'kali-linux', '--', tool, ...args]
      const child = spawn('wsl.exe', wslArgs, {
        cwd: options.cwd || process.cwd(),
        env: { ...process.env, ...(options.env || {}) },
        shell: false,
      })
      let stdout = ''
      let stderr = ''
      const timer = options.timeoutMs ? setTimeout(() => child.kill('SIGKILL'), options.timeoutMs) : null

      child.stdout?.on('data', (d) => (stdout += d.toString()))
      child.stderr?.on('data', (d) => (stderr += d.toString()))

      if (options.input) {
        child.stdin?.write(options.input)
        child.stdin?.end()
      }

      child.on('close', (code) => {
        if (timer) clearTimeout(timer)
        resolve({ ok: code === 0, code, stdout, stderr, method: 'WSL' })
      })
      child.on('error', (err) => {
        if (timer) clearTimeout(timer)
        resolve({ ok: false, code: null, stdout, stderr: String(err), method: 'WSL' })
      })
    })
  }

  private runDocker(tool: string, args: string[], options: RunToolOptions, image: string): Promise<RunResult> {
    return new Promise((resolve) => {
      const workdir = options.cwd || process.cwd()
      const dockerArgs = [
        'run', '--rm', '-i',
        '-v', `${workdir}:/work`,
        '-w', '/work',
        image,
        tool,
        ...args,
      ]

      const child = spawn('docker', dockerArgs, {
        cwd: workdir,
        env: { ...process.env, ...(options.env || {}) },
        shell: false,
      })
      let stdout = ''
      let stderr = ''
      const timer = options.timeoutMs ? setTimeout(() => child.kill('SIGKILL'), options.timeoutMs) : null

      child.stdout?.on('data', (d) => (stdout += d.toString()))
      child.stderr?.on('data', (d) => (stderr += d.toString()))

      if (options.input) {
        child.stdin?.write(options.input)
        child.stdin?.end()
      }

      child.on('close', (code) => {
        if (timer) clearTimeout(timer)
        resolve({ ok: code === 0, code, stdout, stderr, method: 'DOCKER' })
      })
      child.on('error', (err) => {
        if (timer) clearTimeout(timer)
        resolve({ ok: false, code: null, stdout, stderr: String(err), method: 'DOCKER' })
      })
    })
  }
}

export default ToolRunner


