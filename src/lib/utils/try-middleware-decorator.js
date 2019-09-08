module.exports = middlewareFunction => async (req, res, next) => {
  try {
    await middlewareFunction(req, res, next);
  } catch (err) {
    next(err);
  }
};
