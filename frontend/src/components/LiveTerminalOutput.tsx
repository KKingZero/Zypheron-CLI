import React, { useEffect, useRef, useState } from 'react'
import { Terminal, Copy, Download, Search, Maximize2, Minimize2, X } from 'lucide-react'
import toast from 'react-hot-toast'

interface LiveTerminalOutputProps {
  toolName: string
  output: string[]
  isRunning: boolean
  onStop?: () => void
  onClose?: () => void
  className?: string
  maxHeight?: string
  showTimestamps?: boolean
  enableSearch?: boolean
  autoScroll?: boolean
}

const LiveTerminalOutput: React.FC<LiveTerminalOutputProps> = ({
  toolName,
  output,
  isRunning,
  onStop,
  onClose,
  className = '',
  maxHeight = '400px',
  showTimestamps = true,
  enableSearch = true,
  autoScroll = true
}) => {
  const [searchTerm, setSearchTerm] = useState('')
  const [isExpanded, setIsExpanded] = useState(false)
  const [showSearch, setShowSearch] = useState(false)
  const terminalRef = useRef<HTMLDivElement>(null)
  const endRef = useRef<HTMLDivElement>(null)

  // Auto-scroll to bottom when new output arrives
  useEffect(() => {
    if (autoScroll && endRef.current && isRunning) {
      endRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [output, autoScroll, isRunning])

  // Format timestamp
  const getTimestamp = () => {
    const now = new Date()
    return `[${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}]`
  }

  // Copy output to clipboard
  const handleCopy = () => {
    const text = output.join('\n')
    navigator.clipboard.writeText(text)
    toast.success('Output copied to clipboard')
  }

  // Export output to file
  const handleExport = () => {
    const text = output.join('\n')
    const blob = new Blob([text], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${toolName.toLowerCase().replace(/\s+/g, '_')}_${Date.now()}.txt`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    toast.success('Output exported')
  }

  // Filter output based on search
  const filteredOutput = searchTerm
    ? output.filter(line => line.toLowerCase().includes(searchTerm.toLowerCase()))
    : output

  // Syntax highlighting for common patterns
  const highlightLine = (line: string) => {
    // Error patterns
    if (/error|fail|exception|denied/i.test(line)) {
      return <span className="text-red-400">{line}</span>
    }
    // Success patterns
    if (/success|complete|done|found|ok/i.test(line)) {
      return <span className="text-green-400">{line}</span>
    }
    // Warning patterns
    if (/warn|warning|caution/i.test(line)) {
      return <span className="text-yellow-400">{line}</span>
    }
    // Info patterns
    if (/^info:|starting|scanning|checking/i.test(line)) {
      return <span className="text-blue-400">{line}</span>
    }
    // IP addresses
    const ipHighlighted = line.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '<span class="text-cyan-400">$&</span>')
    // URLs
    const urlHighlighted = ipHighlighted.replace(/https?:\/\/[^\s]+/g, '<span class="text-purple-400">$&</span>')
    // Numbers
    const numberHighlighted = urlHighlighted.replace(/\b\d+\b/g, '<span class="text-orange-400">$&</span>')
    
    return <span dangerouslySetInnerHTML={{ __html: numberHighlighted }} />
  }

  return (
    <div className={`bg-[#0d0d0d] border border-terminal-border rounded-lg overflow-hidden ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 bg-[#1a1a1a] border-b border-terminal-border">
        <div className="flex items-center space-x-2">
          <Terminal className={`w-4 h-4 ${isRunning ? 'text-green-400 animate-pulse' : 'text-terminal-muted'}`} />
          <span className="text-sm font-mono text-white">{toolName}</span>
          {isRunning && (
            <span className="flex items-center space-x-1 text-xs text-green-400">
              <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
              <span>Running...</span>
            </span>
          )}
        </div>
        
        <div className="flex items-center space-x-1">
          {enableSearch && (
            <button
              onClick={() => setShowSearch(!showSearch)}
              className="p-1.5 hover:bg-terminal-surface rounded transition-colors text-terminal-muted hover:text-white"
              title="Search output"
            >
              <Search className="w-4 h-4" />
            </button>
          )}
          <button
            onClick={handleCopy}
            className="p-1.5 hover:bg-terminal-surface rounded transition-colors text-terminal-muted hover:text-white"
            title="Copy output"
          >
            <Copy className="w-4 h-4" />
          </button>
          <button
            onClick={handleExport}
            className="p-1.5 hover:bg-terminal-surface rounded transition-colors text-terminal-muted hover:text-white"
            title="Export to file"
          >
            <Download className="w-4 h-4" />
          </button>
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1.5 hover:bg-terminal-surface rounded transition-colors text-terminal-muted hover:text-white"
            title={isExpanded ? 'Minimize' : 'Maximize'}
          >
            {isExpanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
          {onClose && (
            <button
              onClick={onClose}
              className="p-1.5 hover:bg-terminal-surface rounded transition-colors text-terminal-muted hover:text-red-400"
              title="Close terminal"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Search Bar */}
      {showSearch && (
        <div className="px-4 py-2 bg-terminal-surface border-b border-terminal-border">
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search in output..."
            className="w-full px-3 py-1 bg-[#0d0d0d] border border-terminal-border rounded text-sm text-white placeholder-terminal-muted focus:outline-none focus:border-cyan-500"
          />
        </div>
      )}

      {/* Terminal Output */}
      <div 
        ref={terminalRef}
        className="p-4 font-mono text-xs overflow-y-auto overflow-x-auto custom-scrollbar"
        style={{ 
          maxHeight: isExpanded ? '80vh' : maxHeight,
          backgroundColor: '#0a0a0a'
        }}
      >
        {filteredOutput.length === 0 && !isRunning && (
          <div className="text-terminal-muted text-center py-8">
            No output yet. Waiting for tool execution...
          </div>
        )}
        
        {filteredOutput.map((line, index) => (
          <div key={index} className="mb-1 text-gray-300 hover:bg-terminal-surface/30 px-2 py-0.5 rounded">
            {showTimestamps && (
              <span className="text-terminal-muted mr-2">
                {getTimestamp()}
              </span>
            )}
            {highlightLine(line)}
          </div>
        ))}
        
        <div ref={endRef} />
      </div>

      {/* Footer with actions */}
      {(isRunning || onStop) && (
        <div className="flex items-center justify-between px-4 py-2 bg-[#1a1a1a] border-t border-terminal-border">
          <div className="text-xs text-terminal-muted">
            {output.length} lines | {filteredOutput.length !== output.length && `${filteredOutput.length} matching`}
          </div>
          {isRunning && onStop && (
            <button
              onClick={onStop}
              className="px-3 py-1 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 rounded text-red-400 text-xs font-medium transition-colors"
            >
              Stop
            </button>
          )}
        </div>
      )}
    </div>
  )
}

export default LiveTerminalOutput

