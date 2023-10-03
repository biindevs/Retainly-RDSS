# Predicting-Employee-Retention: A Recruitment Decision Support System for Screening Applicants

## Installation Guide

This guide will walk you through the steps needed to set up and run the project on your local machine.

### Prerequisites

Ensure you have the following installed on your machine:

- MySQL 10.4.24-MariaDB or higher
- Python 3.10.6

Besides, you should have the following files from the GitHub repository:

- Python packages and dependencies (mentioned in requirements.txt).
- Database structure and data (found in retention.sql script).

**NOTE:** Your MySQL-MariaDB username and password should be the default, i.e., username = "root" and password = "". The host should be "localhost".

### Installation Steps

1. **Clone the repository:**

   Download or clone the [Predicting-Employee-Retention repository](https://github.com/biindevs/Predicting-Employee-Retention).

2. **Install Python:**

   If not already installed, download and install Python 3.10.6.

3. **Set up the project environment:**

   Open the terminal or command prompt from the project directory (or open the project folder in Visual Studio Code and open the terminal from there) and run the following commands:

   ```bash
   py -m env venv                # Create a virtual environment
   venv\Scripts\activate          # Activate the virtual environment
   pip install -r requirements.txt # Install required Python packages and dependencies
