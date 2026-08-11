#!/bin/bash
cd /home/nefzx/phone-GG/phonegg

# Check git status
git status

# Add all changes
git add .

# Commit changes
git commit -m "$(cat <<'EOF'
Add production deployment configuration for Render

- Add gunicorn to requirements.txt for production WSGI server
- Create Procfile with gunicorn configuration
- Update app.py to use PORT environment variable from Render
- Default port changed back to 5000 for local development

Generated with [Devin](https://devin.ai)

Co-Authored-By: Devin <158243242+devin-ai-integration[bot]@users.noreply.github.com>
EOF
)"

# Push to GitHub
git push origin main