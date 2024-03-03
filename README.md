# Intro

This repository is a blog website built with flask and bootstrap

## Features
- User authentication: Users can register and log in to the application.
- Authorization: Different roles (admin and user) with different permissions.
- Admin role: CRUD operations for managing blog posts.
- User role: Read and comment access to blog posts.
- Responsive design: Built with Bootstrap for a mobile-friendly experience.
- Contact : Users can contact the website owner/Admin by filling out a contact form. When the form is submitted, the website owner/Admin receives an email containing the information sent by the user.


## Getting-Started
1. Install the dependencies:

    ```pip install -r requirements.txt```

2. Set up the database

    ```app.config['SQLALCHEMY_DATABASE_URI'] = YOUR DATABASE```

3. Set up the admin account

4. Run the application

    ```python main.py```

## Deployement
This application is ready for deployment to platforms like <a href="https://render.com/">Render</a> and make sure to set the `DATABASE_URL` environment variable to the SQL database URL, such as PostgreSQL.