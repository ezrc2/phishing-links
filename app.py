from flask import Flask, render_template, request
import pickle
import pandas as pd
from scripts.url_feature_extractor import extract_url_features


app = Flask(__name__)

with open('model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('features.pkl', 'rb') as f:
    features = pickle.load(f)


phishing_df = pd.read_csv('dataset_phishing.csv')
url_features = phishing_df.columns[:55]
phishing_df = phishing_df[url_features]
cols = phishing_df.columns.to_list()


@app.route('/')
def main():
    return render_template('main.html')

@app.route('/', methods=['POST'])
def form():
    url = request.form['text']

    if url.strip() == '':
        return render_template('main.html', link=url, result='Please enter a link')

    link_features = pd.DataFrame([extract_url_features(url)], columns=cols)
    link_features.drop(columns=['url', 'nb_redirection', 'nb_external_redirection'], inplace=True)

    pred = model.predict(link_features[features])
    response = 'legitimate' if pred == 0 else 'phishing'

    return render_template('main.html', link=url, result=response)


if __name__ == '__main__':
    app.run()