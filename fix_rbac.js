const fs = require('fs');
let middleware = fs.readFileSync('backend/src/middleware/rbac.ts', 'utf8');
middleware = middleware.replace(/\.rpc\('get_user_role_permissions'.*?user_uuid: data\.user\.id/g, ".rpc('get_user_access_level', { check_user_id: data.user.id");
middleware = middleware.replace(/\.rpc\('get_user_access_level".*?check_user_id: data\.user\.id/g, ".rpc('get_user_access_level', { check_user_id: data.user.id");
fs.writeFileSync('backend/src/middleware/rbac.ts', middleware);
let authRoutes = fs.readFileSync('backend/src/routes/auth-rbac.ts', 'utf8');
authRoutes = authRoutes.replace(/\.rpc\('get_user_role_permissions'.*?user_uuid: data\.user\.id/g, ".rpc('get_user_access_level', { check_user_id: data.user.id");
fs.writeFileSync('backend/src/routes/auth-rbac.ts', authRoutes);
console.log('✅ Fixed RBAC function calls');
