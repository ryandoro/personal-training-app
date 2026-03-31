# FitBaseAI

FitBaseAI — A full-stack prototype fitness SaaS platform built to streamline workout creation and progress tracking while integrating modern SaaS features like subscriptions and automated communication.

---

## Features
- **Personalized Workout Generator** – Automatically creates workouts for free weight, bodyweight, and machine exercises.  
- **Progress Tracking** – Stores personal records, max weight/reps, and workout history.  
- **FitBaseAI Assistant** – In-app AI assistant for Pro trainers and admins with live app context, grounded knowledge retrieval, and confirmation-based actions.  
- **Gym Catalog Support** – Multi-gym exercise library architecture with trainer-managed, Cloudinary-backed media upload support.  
- **Subscription Management** – Free trial → Premium upgrade flow with automated downgrades to Free tier.  
- **Admin Dashboard** – Manage users, subscriptions, and user data.  
- **Email Delivery** – Automated transactional emails (Postmark).  
- **Role-Based Access** – User tiers (Free, Premium, Pro).  

---

## Tech Stack
- **Backend:** Python (Flask), PostgreSQL  
- **Frontend:** HTML, CSS, JavaScript, Bootstrap  
- **Integrations:** Stripe (payments), Postmark (email)  
- **Other:** Git/GitHub for version control  

---

## Why This Project
I built FitBaseAI after 13 years in the fitness industry to solve real-world challenges I experienced as a trainer and manager:
- Trainers wasting time writing repetitive workouts.  
- Losing track of progress and machine settings.  
- Gyms struggling with subscription flows and retention.  

This prototype shows how fitness workflows can be turned into scalable, intuitive software.

## Future Enhancements
- Expanded analytics in the admin dashboard  

### Registration safeguards
- Run the migration in `sql/202421_create_registration_attempts.sql` to enable rate-limited logging for signup attempts.
- Provide Cloudflare Turnstile keys via the `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY` environment variables to enable the human-verification widget on `/register`.
- Optional environment overrides let you tune throttling thresholds: `REGISTRATION_RATE_LIMIT_WINDOW_HOURS`, `REGISTRATION_RATE_LIMIT_PER_EMAIL`, and `REGISTRATION_RATE_LIMIT_PER_IP`.

### Gym catalog support
- Run `sql/202426_add_gym_catalog_support.sql` to add multi-gym catalog tables/columns if your environment does not auto-run schema updates.
- Trainers can manage gyms and gym-specific exercises at `/trainer/gym_catalog`.
- Catalog mode can be switched between the default FitBaseAI catalog and a selected gym catalog.
- The default baseline gym is seeded as **Western Racquet and Fitness Club** (2500 S Ashland Ave, Green Bay, Wisconsin 54304).
- Direct trainer media uploads require `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, and `CLOUDINARY_API_SECRET`.
- Cloudinary trainer uploads default to the signed presets `fitbaseai_trainer_video_v1` and `fitbaseai_trainer_image_v1`. Override them with `CLOUDINARY_TRAINER_VIDEO_UPLOAD_PRESET` and `CLOUDINARY_TRAINER_IMAGE_UPLOAD_PRESET` if needed.
- Demo videos are limited to `15` seconds and `100MB`; start/end images are limited to `10MB` and must also be portrait.

### FitBaseAI assistant
- FitBaseAI includes an in-app AI assistant for Pro trainers and admin users, exposed through a shared chat panel in the main app shell.
- The assistant combines LLM responses with deterministic app tools so it can answer account, schedule, roster, and training questions using live application data instead of only generative text.
- Action requests such as scheduling, booking, rescheduling, canceling, and workout-related updates are guarded behind an explicit confirmation step before anything is written back to the database.
- The backend maintains per-user conversation threads, message history, pending actions, budget tracking, cached summaries, and risk-flag tables so the assistant behaves like an integrated product feature instead of a stateless chatbot.
- Retrieval is grounded with uploaded coaching manuscripts and a locally stored research corpus, including admin-triggered syncs for approved fitness and health sources.
- Admin controls now include FitBaseAI budget visibility, manuscript upload, research-sync tooling, and corpus status reporting directly inside the dashboard.
- The agent is designed with role-aware access rules so members can access only their own data, trainers can work against linked client data, and admins can access platform-wide controls and summaries.

### FitBaseAI assistant configuration
- The agent schema bootstraps on app startup through the Flask application, so the conversation, document, and budget tables do not require a separate manual migration in normal environments.
- Set `OPENAI_API_KEY` to enable model calls. Optional overrides include `OPENAI_API_URL`, `OPENAI_RESPONSES_URL`, `AGENT_MODEL`, `AGENT_MONTHLY_BUDGET_USD`, `AGENT_INTERNAL_STOP_USD`, `AGENT_MAX_OUTPUT_TOKENS`, and `OPENAI_TIMEOUT_SECONDS`.
- Manuscript ingestion currently supports `.txt`, `.md`, `.docx`, and `.pdf` uploads for internal coaching knowledge retrieval.

---
## 👤 Author
**Ryan Doro**  
- 13 years in the fitness industry (trainer, sales, general manager)  
- Software engineer with experience in Python, Flask, PostgreSQL, JavaScript, Stripe, and Postmark  
- [LinkedIn](https://www.linkedin.com/in/ryandoroprogramming) | [Email](mailto:ryandoro93@gmail.com)
