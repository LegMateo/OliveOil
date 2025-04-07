1.  Email Verification Abuse
Issue: Malicious users can spam /register with valid emails to send thousands of verification links.
Risk: Could lead to high SES bills and potential account suspension.
Planned Fix:
	•	Implement rate limiting per IP (e.g., 5 req/min).
	•	Add CAPTCHA on frontend.
	•	Use async email queue to delay & monitor sends.
Do later: Move email sending to Notification microservice

When you’re ready to scale and introduce background jobs:
	•	Move send_email() logic to the Notification service
	•	Send events to it using RabbitMQ or Redis pub/sub
	•	That microservice can send the actual emails asynchronously

2. Resend Verification Link Logic
	•	Add cooldown to avoid spamming the email server or being used as an open relay.

3.	Timing Attack Prevention ✅ (already implemented)
	•	Use a dummy hash when user doesn’t exist during login to prevent attackers from measuring response time differences.

4. Add Redis Integration (After Production Launch in ECS)

🔧 Purpose:
	•	Token Blacklisting: Prevent refresh tokens from being reused after logout or rotation.
	•	Rate Limiting: Limit repeated requests from the same IP to prevent brute-force attacks, spam, or abuse.
	•	(Optional later: shared caching or session data across services)

🧠 Why Postpone:
	•	Not critical for initial production — system works fine with short-lived tokens and basic validation.
	•	Adding Redis now adds infrastructure and config complexity.
	•	ECS works well without it — Redis can be added later via ElastiCache (preferred for security and scale).

🧩 Integration Plan (Later):
	1.	Use AWS ElastiCache for Redis (production-ready, managed, secure).
	2.	Replace in-memory or “no-blacklist” logic with:
	•	redis.setex() for blacklisting tokens on logout/rotation
	•	redis.incr() + expire() for IP-based request limiting
	3.	Connect via REDIS_URL env variable for flexibility.