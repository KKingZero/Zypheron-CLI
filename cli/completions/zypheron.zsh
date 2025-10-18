#compdef zypheron
# Zypheron CLI - Zsh Completion Script
# Installation: Place in $fpath or /usr/share/zsh/site-functions/_zypheron

_zypheron() {
    local -a commands tools models formats categories
    
    # Main commands
    commands=(
        'chat:Interactive AI chat for security assistance'
        'scan:Security scanning with Kali tools'
        'threat:Threat intelligence analysis'
        'exploit:Exploitation framework integration'
        'recon:Reconnaissance operations'
        'bruteforce:Credential attacks'
        'fuzz:Web fuzzing'
        'osint:OSINT operations'
        'report:Generate security reports'
        'dashboard:Real-time monitoring dashboard'
        'tools:Manage Kali security tools'
        'config:Manage configuration'
        'setup:Setup and configure Zypheron CLI'
        'help:Show help information'
    )
    
    # Available tools
    tools=(
        'nmap:Network exploration and security auditing'
        'nikto:Web server scanner'
        'nuclei:Fast vulnerability scanner'
        'masscan:Fast TCP port scanner'
        'sqlmap:Automatic SQL injection tool'
        'gobuster:Directory/file & DNS busting tool'
        'ffuf:Fast web fuzzer'
        'wfuzz:Web application bruteforcer'
        'metasploit:Penetration testing framework'
        'hydra:Network logon cracker'
        'john:Password cracker'
        'hashcat:Advanced password recovery'
        'subfinder:Subdomain discovery tool'
        'amass:In-depth DNS enumeration'
        'theharvester:E-mail and subdomain harvester'
        'recon-ng:Web reconnaissance framework'
        'aircrack-ng:WiFi security auditing tools'
        'wireshark:Network protocol analyzer'
        'burpsuite:Web application security testing'
        'zaproxy:OWASP Zed Attack Proxy'
    )
    
    # AI models
    models=(
        'gpt-4:OpenAI GPT-4'
        'gpt-3.5-turbo:OpenAI GPT-3.5 Turbo'
        'claude-3-opus:Anthropic Claude 3 Opus'
        'claude-3-sonnet:Anthropic Claude 3 Sonnet'
        'gemini-pro:Google Gemini Pro'
    )
    
    # Output formats
    formats=(
        'text:Plain text format'
        'json:JSON format'
        'xml:XML format'
        'html:HTML format'
        'pdf:PDF format'
        'markdown:Markdown format'
    )
    
    # Tool categories
    categories=(
        'scanner:Network and vulnerability scanners'
        'exploit:Exploitation frameworks'
        'bruteforce:Password and credential attacks'
        'reconnaissance:Information gathering'
        'web:Web application testing'
        'wireless:Wireless security'
        'forensics:Network analysis and forensics'
        'osint:Open source intelligence'
    )
    
    _arguments -C \
        '1: :->command' \
        '*:: :->args'
    
    case $state in
        command)
            _describe 'command' commands
            ;;
        args)
            case $words[1] in
                scan)
                    _arguments \
                        '1: :_hosts' \
                        '--target[Target URL or IP]:target:_hosts' \
                        '--tool[Specific tool to use]:tool:->tools' \
                        '--tools[Comma-separated list of tools]:tools:' \
                        '--ports[Port range]:ports:' \
                        '--web[Web application focus]' \
                        '--full[Full pentest suite]' \
                        '--fast[Quick scan]' \
                        '--ai-guided[AI-guided scanning]' \
                        '--ai-analysis[Include AI analysis]' \
                        '--output[Output file]:file:_files' \
                        '--format[Output format]:format:->formats' \
                        '--nmap-args[Additional nmap arguments]:args:' \
                        '--timeout[Timeout in seconds]:seconds:' \
                        '--stream[Stream output in real-time]'
                    
                    case $state in
                        tools)
                            _describe 'tool' tools
                            ;;
                        formats)
                            _describe 'format' formats
                            ;;
                    esac
                    ;;
                    
                chat)
                    _arguments \
                        '1: :_message' \
                        '--model[AI model to use]:model:->models' \
                        '--continue[Continue previous conversation]:session:' \
                        '--export[Export conversation]:file:_files' \
                        '--no-stream[Disable streaming responses]'
                    
                    case $state in
                        models)
                            _describe 'model' models
                            ;;
                    esac
                    ;;
                    
                tools)
                    _arguments \
                        '1: :->tools-command' \
                        '*:: :->tools-args'
                    
                    case $state in
                        tools-command)
                            local -a tools_commands
                            tools_commands=(
                                'check:Check installed tools'
                                'list:List all available tools'
                                'info:Get information about a tool'
                                'suggest:Suggest best tool for a task'
                                'install:Install a specific tool'
                                'install-all:Install all missing tools'
                            )
                            _describe 'tools command' tools_commands
                            ;;
                        tools-args)
                            case $words[1] in
                                check|list)
                                    _arguments \
                                        '--category[Filter by category]:category:->categories' \
                                        '--installed[Show only installed tools]' \
                                        '--missing[Show only missing tools]'
                                    
                                    case $state in
                                        categories)
                                            _describe 'category' categories
                                            ;;
                                    esac
                                    ;;
                                info|install)
                                    _describe 'tool' tools
                                    ;;
                                install-all)
                                    _arguments \
                                        '--yes[Skip confirmation prompt]' \
                                        '--critical-only[Install only critical priority tools]' \
                                        '--high-priority[Install critical and high priority tools]'
                                    ;;
                                suggest)
                                    local -a tasks
                                    tasks=(
                                        'scan:Scanning and enumeration'
                                        'exploit:Exploitation'
                                        'bruteforce:Credential attacks'
                                        'recon:Reconnaissance'
                                        'web:Web application testing'
                                        'osint:OSINT gathering'
                                        'wireless:Wireless attacks'
                                    )
                                    _describe 'task' tasks
                                    ;;
                            esac
                            ;;
                    esac
                    ;;
                    
                config)
                    _arguments \
                        '1: :->config-command' \
                        '*:: :->config-args'
                    
                    case $state in
                        config-command)
                            local -a config_commands
                            config_commands=(
                                'set:Set a configuration value'
                                'get:Get configuration value'
                                'delete:Delete a configuration value'
                                'wizard:Interactive configuration wizard'
                                'path:Show configuration file path'
                            )
                            _describe 'config command' config_commands
                            ;;
                    esac
                    ;;
                    
                threat)
                    _arguments \
                        '1: :->threat-command' \
                        '*:: :->threat-args'
                    
                    case $state in
                        threat-command)
                            local -a threat_commands
                            threat_commands=(
                                'ip:Analyze IP address'
                                'domain:Analyze domain'
                                'hash:Analyze file hash'
                            )
                            _describe 'threat command' threat_commands
                            ;;
                    esac
                    ;;
                    
                report)
                    _arguments \
                        '1: :->report-command' \
                        '*:: :->report-args'
                    
                    case $state in
                        report-command)
                            local -a report_commands
                            report_commands=(
                                'generate:Generate report from scan'
                                'templates:List available templates'
                            )
                            _describe 'report command' report_commands
                            ;;
                        report-args)
                            case $words[1] in
                                generate)
                                    _arguments \
                                        '--scan[Scan ID]:scan-id:' \
                                        '--format[Report format]:format:->formats' \
                                        '--output[Output file]:file:_files'
                                    
                                    case $state in
                                        formats)
                                            _describe 'format' formats
                                            ;;
                                    esac
                                    ;;
                            esac
                            ;;
                    esac
                    ;;
                    
                exploit|recon|bruteforce|fuzz|osint|dashboard|setup)
                    # These would have their specific completions
                    _message 'target or options'
                    ;;
            esac
            ;;
    esac
}

_zypheron "$@"

# Add Kali-style prompt hint
if [[ -o interactive ]]; then
    echo "⚡ Zypheron CLI zsh completions loaded"
fi

