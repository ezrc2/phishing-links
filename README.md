# phishing-links

### Requirements
```
pip install -r requirements.txt
```

### How to run
```
flask run
```

Dataset and feature extraction scripts are from https://data.mendeley.com/datasets/c2gw7fy2j4/3. I took out the url-only function from **feature_extractor.py** and created a new file **url_feature_extractor.py**, and added null checks to **url_features.py**

It is interesting that the model can correctly predict very complex phishing urls, but some very short and simple urls like 'youtube.com' are classified incorrectly, I think because there aren't very many basic urls with very few features in the dataset.