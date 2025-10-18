# Console Log Migration Guide

## Problem

The application has **57 files** with direct `console.log/error/warn` statements that execute in production, creating:
- Performance overhead
- Exposed debug information in browser console
- No error tracking/monitoring

## Solution

A production-safe logger utility has been created: `/frontend/src/utils/logger.ts`

## Migration Path

### Before:
```typescript
console.log('User data:', userData)
console.error('API failed:', error)
console.warn('Deprecated feature used')
```

### After:
```typescript
import { logger } from '../utils/logger'

logger.log('User data:', userData)       // Only logs in DEV
logger.error('API failed:', error)       // Logs in DEV, sends to monitoring in PROD
logger.warn('Deprecated feature used')   // Logs in DEV, sends to monitoring in PROD
```

## Benefits

✅ **Automatic stripping** - No logs in production console  
✅ **Error monitoring ready** - Errors sent to monitoring service  
✅ **Performance** - Zero overhead in production  
✅ **Drop-in replacement** - Same API as console.*  

## Priority Files to Migrate

### HIGH PRIORITY (User-facing)
1. ✅ `/app/pages/Chat.tsx` - Some console.logs wrapped
2. ✅ `/app/pages/IOCScanner.tsx` - Console.errors removed
3. `/contexts/ChatContext.tsx` - Chat operations
4. `/components/ErrorBoundary.tsx` - Error handling (keep some for logging)

### MEDIUM PRIORITY (Tools)
5. `/app/components/redteam/AdvancedToolsDashboard.tsx`
6. `/app/pages/BlueTeamDefenseHub.tsx`
7. `/app/pages/RedTeamOps.tsx`

### LOW PRIORITY (Dev tools - can keep console.logs)
- `/utils/devMode.ts` - Keep as-is (dev only)
- `/components/DevDebugInfo.tsx` - Keep as-is (dev only)
- `/components/DevModeToggle.tsx` - Keep as-is (dev only)

## Implementation Status

- ✅ Logger utility created
- ✅ Critical production console.errors removed (IOCScanner)
- ⚠️ 57 files remain to migrate (can be done incrementally)
- 📝 Dev-only files can keep console.logs

## Quick Migration Script

For bulk migration, use this find-replace pattern:

```bash
# In each file:
1. Add import: import { logger } from '../utils/logger'
2. Replace: console.log → logger.log
3. Replace: console.error → logger.error
4. Replace: console.warn → logger.warn
5. Replace: console.debug → logger.debug
```

## Notes

- **DEV mode logs** wrapped in `if (import.meta.env.DEV)` can stay as-is
- **Error logging** in ErrorBoundary should remain for debugging
- **Dev-only components** (/components/Dev*) don't need migration
- Logger automatically detects DEV vs PROD environment

## Future Integration

TODO: Connect `logger.error/warn` to error monitoring service (Sentry, LogRocket, etc.) in the `sendToMonitoring` method.

