#!/usr/bin/env bash
# Zypheron CLI - Bash Completion Script
# Installation: source this file or copy to /etc/bash_completion.d/zypheron

_zypheron_completions() {
    local cur prev commands tools
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    # Main commands
    commands="chat scan threat exploit recon bruteforce fuzz osint report dashboard tools config setup help"
    
    # Available tools
    tools="nmap nikto nuclei masscan sqlmap gobuster ffuf wfuzz metasploit hydra john hashcat subfinder amass theharvester recon-ng aircrack-ng wireshark burpsuite zaproxy"
    
    # Models
    models="gpt-4 gpt-3.5-turbo claude-3-opus claude-3-sonnet gemini-pro"
    
    # Tool categories
    categories="scanner exploit bruteforce reconnaissance web wireless forensics osint"
    
    case "${COMP_CWORD}" in
        1)
            # Complete main command
            COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
            return 0
            ;;
    esac
    
    case "${prev}" in
        zypheron)
            COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
            return 0
            ;;
            
        # Scan command options
        scan)
            COMPREPLY=( $(compgen -W "--target --tool --tools --ports --web --full --fast --ai-guided --ai-analysis --output --format --nmap-args --timeout --stream" -- ${cur}) )
            return 0
            ;;
            
        # Chat command options
        chat)
            COMPREPLY=( $(compgen -W "--model --continue --export --no-stream" -- ${cur}) )
            return 0
            ;;
            
        # Tools command subcommands
        tools)
            COMPREPLY=( $(compgen -W "check list info suggest install install-all" -- ${cur}) )
            return 0
            ;;
            
        # Config command subcommands
        config)
            COMPREPLY=( $(compgen -W "set get delete wizard path" -- ${cur}) )
            return 0
            ;;
            
        # Threat command subcommands
        threat)
            COMPREPLY=( $(compgen -W "ip domain hash" -- ${cur}) )
            return 0
            ;;
            
        # Report command subcommands
        report)
            COMPREPLY=( $(compgen -W "generate templates" -- ${cur}) )
            return 0
            ;;
            
        # Option values
        --tool|-t)
            COMPREPLY=( $(compgen -W "${tools}" -- ${cur}) )
            return 0
            ;;
            
        --tools)
            # Allow comma-separated list
            if [[ ${cur} == *,* ]]; then
                local prefix="${cur%,*},"
                local suffix="${cur##*,}"
                COMPREPLY=( $(compgen -W "${tools}" -- ${suffix}) )
                COMPREPLY=( "${COMPREPLY[@]/#/$prefix}" )
            else
                COMPREPLY=( $(compgen -W "${tools}" -- ${cur}) )
            fi
            return 0
            ;;
            
        --model|-m)
            COMPREPLY=( $(compgen -W "${models}" -- ${cur}) )
            return 0
            ;;
            
        --format)
            COMPREPLY=( $(compgen -W "text json xml html pdf markdown" -- ${cur}) )
            return 0
            ;;
            
        --category|-c)
            COMPREPLY=( $(compgen -W "${categories}" -- ${cur}) )
            return 0
            ;;
            
        --output|-o|--export|-e)
            # Complete filenames
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
    esac
    
    # If we're after a flag that takes no argument, suggest next flags
    case "${prev}" in
        --web|--full|--fast|--ai-guided|--ai-analysis|--stream|--no-stream|--installed|--missing|--deep|--subdomain|--critical-only|--high-priority)
            local cmd="${COMP_WORDS[1]}"
            case "${cmd}" in
                scan)
                    COMPREPLY=( $(compgen -W "--target --tool --tools --ports --web --full --fast --ai-guided --ai-analysis --output --format --timeout" -- ${cur}) )
                    ;;
                tools)
                    COMPREPLY=( $(compgen -W "--category --installed --missing --yes --critical-only --high-priority" -- ${cur}) )
                    ;;
            esac
            return 0
            ;;
        
        # After tools install/install-all, suggest tool names or options
        install|install-all)
            if [[ "${COMP_WORDS[1]}" == "tools" ]]; then
                if [[ "${COMP_WORDS[2]}" == "install" && "${COMP_CWORD}" == "3" ]]; then
                    # Complete tool names for 'tools install <tool>'
                    COMPREPLY=( $(compgen -W "${tools}" -- ${cur}) )
                elif [[ "${COMP_WORDS[2]}" == "install-all" ]]; then
                    # Complete options for 'tools install-all'
                    COMPREPLY=( $(compgen -W "--yes --critical-only --high-priority" -- ${cur}) )
                fi
            fi
            return 0
            ;;
    esac
}

complete -F _zypheron_completions zypheron

# Add Kali-style prompt hint
if [[ -n "$PS1" ]]; then
    echo "⚡ Zypheron CLI bash completions loaded"
fi

