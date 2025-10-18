import { Router } from 'express'
import { authMiddleware } from '../middleware/auth'
import ToolRegistry from '../services/toolRegistry'

const router = Router()
const registry = new ToolRegistry()

// List known tools (with last known install flags)
router.get('/list', authMiddleware, async (req, res) => {
  return res.json({ tools: registry.list() })
})

// Detect installed tools (native/WSL)
router.get('/detect', authMiddleware, async (req, res) => {
  try {
    const tools = await registry.detectInstalled()
    return res.json({ tools })
  } catch (e: any) {
    return res.status(500).json({ error: 'detection_failed', message: e.message })
  }
})

// Run a tool by id with args
router.post('/run/:id', authMiddleware, async (req, res) => {
  try {
    const id = req.params.id
    const args = Array.isArray(req.body?.args) ? req.body.args : []
    const result = await registry.run(id, args)
    return res.json(result)
  } catch (e: any) {
    return res.status(500).json({ error: 'execution_failed', message: e.message })
  }
})

export default router


