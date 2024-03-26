const express = require('express')
const router = express.Router()

const loginRoute = require('../login')
const controlRoute = require('./route_control')

router.use(loginRoute)
router.use(controlRoute)

module.exports = router