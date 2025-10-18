/**
 * Chat Command - Interactive AI Chat with Claude-style streaming
 */

import { Command } from 'commander';
import chalk from 'chalk';
import inquirer from 'inquirer';
import axios from 'axios';
import { KaliTheme, StatusIndicators, Icons } from '../ui/themes/kali';
import { showInfo, showError } from '../ui/components/banner';

export function chatCommand(program: Command): void {
  program
    .command('chat [question]')
    .description('Interactive AI chat for security assistance')
    .option('-m, --model <model>', 'AI model to use (gpt-4, claude, gpt-3.5)', 'gpt-4')
    .option('-c, --continue <session>', 'Continue previous conversation')
    .option('-e, --export <file>', 'Export conversation to file')
    .option('--no-stream', 'Disable streaming responses')
    .action(async (question, options) => {
      await runChat(question, options);
    });
}

async function runChat(question: string | undefined, options: any): Promise<void> {
  // Show chat header
  console.log(chalk.hex(KaliTheme.primary).bold('\n╔═══════════════════════════════════════╗'));
  console.log(chalk.hex(KaliTheme.primary).bold('║  ZYPHERON AI ASSISTANT               ║'));
  console.log(chalk.hex(KaliTheme.primary).bold('╚═══════════════════════════════════════╝\n'));
  
  console.log(chalk.hex(KaliTheme.claudeAccent)(`${Icons.robot} Model: ${chalk.bold(options.model)}`));
  console.log(chalk.hex(KaliTheme.muted)('Type "exit" or press Ctrl+C to quit\n'));

  const conversationHistory: Array<{ role: string; content: string }> = [];

  // Single question mode
  if (question) {
    await askQuestion(question, options.model, conversationHistory, options.stream);
    return;
  }

  // Interactive mode
  while (true) {
    const { userInput } = await inquirer.prompt([
      {
        type: 'input',
        name: 'userInput',
        message: chalk.hex(KaliTheme.accent)('You:'),
        prefix: '',
      },
    ]);

    if (!userInput || userInput.toLowerCase() === 'exit' || userInput.toLowerCase() === 'quit') {
      console.log(chalk.hex(KaliTheme.info)('\nExiting chat. Stay secure! 🛡️\n'));
      break;
    }

    if (userInput.toLowerCase() === 'clear') {
      console.clear();
      continue;
    }

    if (userInput.toLowerCase() === 'history') {
      showConversationHistory(conversationHistory);
      continue;
    }

    await askQuestion(userInput, options.model, conversationHistory, options.stream);
  }

  // Export if requested
  if (options.export) {
    await exportConversation(conversationHistory, options.export);
  }
}

async function askQuestion(
  question: string,
  model: string,
  history: Array<{ role: string; content: string }>,
  stream: boolean
): Promise<void> {
  // Add to history
  history.push({ role: 'user', content: question });

  try {
    // Show AI is thinking
    console.log(chalk.hex(KaliTheme.claudeAccent)(`\n${Icons.robot} Zypheron:`));
    console.log(chalk.hex(KaliTheme.muted)('─'.repeat(60)));

    // Call backend API (this would integrate with your existing backend)
    const apiUrl = process.env.VITE_API_URL || 'http://localhost:3001';
    
    if (stream) {
      await streamResponse(apiUrl, question, model, history);
    } else {
      await getResponse(apiUrl, question, model, history);
    }

    console.log(chalk.hex(KaliTheme.muted)('─'.repeat(60)));
    console.log();
  } catch (error: any) {
    showError(`Failed to get AI response: ${error.message}`);
  }
}

async function streamResponse(
  apiUrl: string,
  question: string,
  model: string,
  history: Array<{ role: string; content: string }>
): Promise<void> {
  // This would implement SSE or WebSocket streaming
  // For now, show a placeholder
  const response = chalk.hex(KaliTheme.foreground)(
    `This is where the AI response would stream in real-time.\n\n` +
    `Your question: "${question}"\n` +
    `Model: ${model}\n\n` +
    `The actual implementation would connect to your backend API at:\n` +
    `${apiUrl}/api/chat\n\n` +
    `For a real streaming experience, this would:\n` +
    `1. Send the question to the backend\n` +
    `2. Receive tokens as they're generated\n` +
    `3. Display them with Claude-style formatting\n` +
    `4. Include code syntax highlighting\n` +
    `5. Support markdown rendering`
  );
  
  // Simulate streaming effect
  const words = response.split(' ');
  for (const word of words) {
    process.stdout.write(word + ' ');
    await new Promise(resolve => setTimeout(resolve, 30));
  }
  console.log('\n');
  
  history.push({ role: 'assistant', content: response });
}

async function getResponse(
  apiUrl: string,
  question: string,
  model: string,
  history: Array<{ role: string; content: string }>
): Promise<void> {
  // Non-streaming response
  try {
    const response = await axios.post(`${apiUrl}/api/chat/message`, {
      message: question,
      model: model,
      conversationHistory: history,
    });

    const aiResponse = response.data.response || 'No response received';
    console.log(chalk.hex(KaliTheme.foreground)(aiResponse));
    console.log();
    
    history.push({ role: 'assistant', content: aiResponse });
  } catch (error: any) {
    console.log(chalk.hex(KaliTheme.foreground)(
      `Backend integration would connect here.\n\n` +
      `Question: "${question}"\n` +
      `Model: ${model}\n\n` +
      `The response would come from your existing backend API.`
    ));
    console.log();
  }
}

function showConversationHistory(history: Array<{ role: string; content: string }>): void {
  console.log(chalk.hex(KaliTheme.primary).bold('\n╔═══ CONVERSATION HISTORY ═══════════════╗\n'));
  
  history.forEach((msg, index) => {
    const isUser = msg.role === 'user';
    const icon = isUser ? '👤' : Icons.robot;
    const color = isUser ? KaliTheme.accent : KaliTheme.claudeAccent;
    const label = isUser ? 'You' : 'Zypheron';
    
    console.log(chalk.hex(color).bold(`${icon} ${label}:`));
    console.log(chalk.hex(KaliTheme.foreground)(msg.content.substring(0, 100)));
    if (msg.content.length > 100) {
      console.log(chalk.hex(KaliTheme.muted)('  ... (truncated)'));
    }
    console.log();
  });
  
  console.log(chalk.hex(KaliTheme.primary).bold('╚' + '═'.repeat(42) + '╝\n'));
}

async function exportConversation(
  history: Array<{ role: string; content: string }>,
  filename: string
): Promise<void> {
  const fs = await import('fs/promises');
  
  let content = '# Zypheron Chat Export\n\n';
  content += `Date: ${new Date().toISOString()}\n\n`;
  content += '---\n\n';
  
  history.forEach(msg => {
    const label = msg.role === 'user' ? '👤 You' : '🤖 Zypheron';
    content += `## ${label}\n\n${msg.content}\n\n`;
  });
  
  await fs.writeFile(filename, content, 'utf-8');
  showInfo(`Conversation exported to ${filename}`);
}

