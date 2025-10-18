import React, { useState, useRef, useEffect } from 'react'
import { Send } from 'lucide-react'
import { useChat } from '../../contexts/ChatContext'
import ReactMarkdown from 'react-markdown'
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { oneDark } from 'react-syntax-highlighter/dist/esm/styles/prism'
import MobileLayout from '../../components/MobileLayout'

const MobileChat = () => {
  const [input, setInput] = useState('')
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  
  const {
    currentSession,
    createNewSession,
    sendMessage,
    isLoading
  } = useChat()

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [currentSession?.messages])

  useEffect(() => {
    if (!currentSession) {
      createNewSession()
    }
  }, [currentSession, createNewSession])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!input.trim() || isLoading) return

    await sendMessage(input)
    setInput('')
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e)
    }
  }

  return (
    <MobileLayout>
      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto px-4 pb-4 overflow-x-hidden w-full min-w-0">
        {!currentSession?.messages.length && (
          <div className="text-center py-8">
            <div className="text-zypheron-500 mb-2">🐍</div>
            <p className="text-terminal-muted text-sm">
              Ready for cybersecurity assistance
            </p>
          </div>
        )}

        {currentSession?.messages.map((message) => (
          <div key={message.id} className="mb-4">
            {message.role === 'user' ? (
              <div className="flex justify-end">
                <div className="bg-zypheron-500/10 border border-zypheron-500/30 rounded-lg p-3 max-w-[85%] break-words overflow-hidden">
                  <div className="text-zypheron-400 text-xs mb-1">You</div>
                  <div className="text-terminal-text">{message.content}</div>
                </div>
              </div>
            ) : (
              <div className="flex justify-start">
                <div className="bg-terminal-surface border border-terminal-border rounded-lg p-3 max-w-[85%] break-words overflow-hidden min-w-0">
                  <div className="text-green-400 text-xs mb-1">Zypheron</div>
                  <div className="prose prose-invert prose-sm max-w-none">
                                         <ReactMarkdown
                       components={{
                         code({ className, children, ...props }: any) {
                           const match = /language-(\w+)/.exec(className || '')
                           const isInline = !className || !match
                           
                           return isInline ? (
                             <code className="bg-terminal-border px-1 py-0.5 rounded text-zypheron-400 text-xs" {...props}>
                               {children}
                             </code>
                           ) : (
                             <SyntaxHighlighter
                               style={oneDark as any}
                               language={match[1]}
                               PreTag="div"
                               customStyle={{ fontSize: '12px' }}
                             >
                               {String(children).replace(/\n$/, '')}
                             </SyntaxHighlighter>
                           )
                         }
                       }}
                     >
                       {message.content}
                     </ReactMarkdown>
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}

        {isLoading && (
          <div className="flex justify-start">
            <div className="bg-terminal-surface border border-terminal-border rounded-lg p-3">
              <div className="text-green-400 text-xs mb-1">Zypheron</div>
              <div className="flex items-center space-x-2">
                <div className="flex space-x-1">
                  <div className="w-2 h-2 bg-zypheron-500 rounded-full animate-bounce"></div>
                  <div className="w-2 h-2 bg-zypheron-500 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
                  <div className="w-2 h-2 bg-zypheron-500 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                </div>
                <span className="text-terminal-muted text-sm">Analyzing...</span>
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Terminal Input */}
      <div className="bg-terminal-surface border-t border-terminal-border px-4 py-4">
        <form onSubmit={handleSubmit} className="flex items-end space-x-3">
          <div className="flex-1">
            <div className="flex items-center bg-terminal-bg border border-terminal-border rounded-lg px-3 py-2">
              <span className="text-zypheron-500 font-mono text-sm mr-2">{'>'}_</span>
              <textarea
                ref={textareaRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Enter command or query..."
                className="flex-1 bg-transparent text-terminal-text placeholder-terminal-muted font-mono text-sm resize-none outline-none min-h-[24px] max-h-24"
                disabled={isLoading}
                rows={1}
                style={{
                  height: 'auto',
                  minHeight: '24px'
                }}
                onInput={(e) => {
                  const target = e.target as HTMLTextAreaElement
                  target.style.height = 'auto'
                  target.style.height = `${Math.min(target.scrollHeight, 96)}px`
                }}
              />
            </div>
          </div>
          
          <button
            type="submit"
            disabled={!input.trim() || isLoading}
            className="bg-zypheron-500 hover:bg-zypheron-600 disabled:opacity-50 disabled:cursor-not-allowed text-white p-2 rounded-lg transition-colors"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </MobileLayout>
  )
}

export default MobileChat 