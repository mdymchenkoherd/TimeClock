function requireLogin(req, res, next) {
  if (req.session.user) return next();

  // API: JSON error, not HTML redirect
  if (req.originalUrl.startsWith('/api/')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  return res.redirect('/login');
}

function requireAdmin(req, res, next) {
  if (req.session.user?.role === 'admin') return next();

  if (req.originalUrl.startsWith('/api/')) {
    return res.status(403).json({ error: 'Forbidden: Admins only' });
  }
  return res.status(403).send('Forbidden: Admins only');
}

module.exports = { requireLogin, requireAdmin };
