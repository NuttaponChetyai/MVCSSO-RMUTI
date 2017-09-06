using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using MVCSSO.Models;
namespace MVCSSO.Controllers
{
    public class ManageController : Controller
    {
        // GET: Manage
        public ActionResult Index(ModelSSO model)
        {
            ViewBag.Data = model;
            return View();
        }
    }
}