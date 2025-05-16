from flask import Flask, request, render_template, render_template_string, redirect, url_for

app = Flask(__name__)

@app.route("/")
def home():
	return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def chall():
	if request.method == "POST":
		name = request.form['user']
		template = '''
			<html lang="en">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>Hacker's Forum Landing Page</title>
				<style>
					body {
						margin: 0;
						padding: 0;
						background-color: #000;
						color: #0f0;
						font-family: 'Courier New', Courier, monospace;
						line-height: 1.6;
					}

					.header {
						background: #0f0;
						color: #000;
						padding: 1rem 0;
						text-align: center;
					}

					.main-content {
						padding: 2rem;
					}

					.news-section {
						margin: 2rem 0;
					}

					.news-item {
						background-color: #111;
						margin-bottom: 1rem;
						padding: 1rem;
						border-left: 4px solid #0f0;
					}

					.news-item h3 {
						margin-top: 0;
					}

					.footer {
						text-align: center;
						padding: 1rem 0;
						background: #111;
					}

					@media (max-width: 600px) {
						.header, .footer {
							padding: 0.5rem 0;
						}

						.main-content {
							padding: 1rem;
						}
					}
				</style>
			</head>
			<body>
				<header class="header">
					<h1>Welcome to the Hacker's Forum</h1>
				</header>
				<main class="main-content">
					<section class="news-section">
						<h2>Latest News</h2>
						<article class="news-item">
							<h3>News Title Placeholder</h3>
							<p>Summary of the news article or update...</p>
						</article>
						<article class="news-item">
							<h3>News Title Placeholder</h3>
							<p>Summary of the news article or update...</p>
						</article>
						<article class="news-item">
							<h3>News Title Placeholder</h3>
							<p>Summary of the news article or update...</p>
						</article>
						<article class="news-item">
							<h3>News Title Placeholder</h3>
							<p>Summary of the news article or update...</p>
						</article>
						<article class="news-item">
							<h3>News Title Placeholder</h3>
							<p>Summary of the news article or update...</p>
						</article>
						<article class="news-item">
							<h3>News Title Placeholder</h3>
							<p>Summary of the news article or update...</p>
						</article>
						<!-- Repeat the article block for more news items -->
					</section>
				</main>
				<footer class="footer">
					<p>&copy; 2024 Hacker's Forum. All rights reserved.</p>
				</footer>
			</body>

			<!-- For debugging use only -->
			<!-- ======================================== -->
			<!-- Username : %s  -->
			<!-- ======================================== -->

			</html>
		''' % name

		return render_template_string(template)


@app.route("/logout")
def logout():
	return redirect(url_for('home'))

if __name__ == "__main__":
	app.run(port=5000)
