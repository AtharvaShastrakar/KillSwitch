import { Router } from 'express';
import { HttpError } from '../services.js';

export function agentRouter(svc) {
  const r = Router();

  r.post('/enroll', (req, res) => {
    const { enrollmentToken, serial, hostname, os, agentVersion } = req.body || {};
    res.json(svc.enroll({ enrollmentToken, serial, hostname, os, agentVersion }));
  });

  // Every other agent call is authenticated with the per-device bearer token.
  r.use((req, _res, next) => {
    const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
    const device = m && svc.deviceFromToken(m[1]);
    if (!device) return next(new HttpError(401, 'unknown device'));
    req.device = device;
    next();
  });

  r.post('/heartbeat', (req, res) => res.json(svc.heartbeat(req.device, req.body)));
  r.post('/ack', (req, res) => res.json(svc.ack(req.device, req.body || {})));
  return r;
}
