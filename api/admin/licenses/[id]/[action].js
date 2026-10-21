import handleRoute from "../../../../lib/handler.js";

export default (req, res) => handleRoute(
  `admin/licenses/${req.query.id}/${req.query.action}`,
  req,
  res
);
