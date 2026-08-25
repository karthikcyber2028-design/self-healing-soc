SELF-HEALING SOC - RENDER DEPLOYMENT (quick guide)
===================================================

This folder is ready to deploy on Render. The GitHub repo has already
been pushed for you.

DEPLOY STEPS (~3 minutes)
-------------------------
1. Go to:  https://dashboard.render.com
2. Sign in  ->  choose "Sign in with GitHub"
3. Click  "New +"  ->  "Web Service"
4. If asked, click "Connect GitHub" and allow access to the repo:
       self-healing-soc
5. Select the repo  self-healing-soc
6. Render will detect render.yaml automatically.
   Confirm settings shown are:
     Runtime:        Python 3.11.9
     Build Command:  pip install -r requirements.txt
     Start Command:  uvicorn main:app --host 0.0.0.0 --port $PORT
7. Click  "Create Web Service"  (free plan is fine)
8. Wait ~4-6 minutes for the first build.
9. Open your app URL + /dashboard   e.g.
       https://self-healing-soc-xxxx.onrender.com/dashboard

LOGIN (same as local demo)
--------------------------
  admin   / Admin@12345
  analyst / Analyst@12345
  viewer  / Viewer@12345

FREE PLAN NOTES
---------------
- The service sleeps after ~15 min without visitors; the next visit
  takes ~50 seconds to wake up.
- SQLite storage is temporary: incidents/events reset when the service
  redeploys or restarts. Perfect for demos, not for permanent data.
- Everything is simulated/synthetic. No real systems are touched.
