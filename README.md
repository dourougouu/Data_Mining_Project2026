# Network Intrusion Detection on CIC-IDS-2017

Exploratory analysis, supervised classification and unsupervised clustering of network traffic for cyber-attack detection, built on the **CIC-IDS-2017** dataset (~2.8M flows, 78 features, 15 traffic classes).

Course project for *Data Mining and Learning Algorithms* (Spring 2025–26), Computer Engineering & Informatics Department (CEID), University of Patras.

**Stack:** Python · pandas · NumPy · scikit-learn · SciPy · NetworkX · Matplotlib · Seaborn

---

## Highlights

- Cleaned and merged **8 CSV files (2.83M rows)** into a dataset of **2.52M rows** by removing NaN/Inf values, duplicates and physically impossible negative values.
- Reduced **78 features to 47** using documented criteria: zero variance and graph-based grouping of highly correlated features (|r| > 0.95).
- Handled extreme class imbalance (**BENIGN 83.1%**, Heartbleed 11 samples) with `class_weight='balanced'` and macro-averaged metrics instead of accuracy.
- Compared **Logistic Regression, Decision Tree and Random Forest**, each tuned with Grid Search in two ways: a hold-out validation set and 3-fold cross-validation.
- Compared **K-Means, Hierarchical clustering and DBSCAN** with Silhouette and Davies–Bouldin, then interpreted the clusters against the ground-truth labels.

---

## Dataset

[CIC-IDS-2017](https://www.unb.ca/cic/datasets/ids-2017.html) (Canadian Institute for Cybersecurity), also available on [Kaggle](https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset). It contains labelled flow-level features (durations, packet counts and lengths, inter-arrival times, TCP flag counts, window sizes, etc.) for one week of benign and attack traffic.

The target column is `Label` (15 classes): BENIGN, DoS Hulk, DDoS, PortScan, DoS GoldenEye, FTP-Patator, DoS slowloris, DoS Slowhttptest, SSH-Patator, Bot, Web Attack (Brute Force / XSS / SQL Injection), Infiltration, Heartbleed.

The data is **not included in this repository**. See [Setup](#setup).

---

## Project structure

| Part | What it covers |
|---|---|
| **1. Exploratory Data Analysis** | Merging files, structure and dtypes, Inf/NaN/duplicate handling, target distribution, descriptive statistics, histograms and boxplots, correlation heatmap, feature selection |
| **2. Classification** | Stratified train/validation/test split, scaling, imbalance handling, Grid Search with and without cross-validation, final evaluation on a held-out test set |
| **3. Clustering** | K-Means (elbow + silhouette), Hierarchical (linkage comparison + dendrogram), DBSCAN (k-distance graph + parameter grid), PCA visualisation, comparison against `Label` |

Everything lives in a single notebook: `DataMining_Project_DrougkaM_1100545.ipynb`.

---

## Methodology and results

### 1. Exploratory Data Analysis and preprocessing

| Step | Result |
|---|---|
| Merged dataset | 2,830,743 rows × 79 columns |
| Inf values (`Flow Bytes/s`, `Flow Packets/s`) → NaN → dropped | 2,867 rows (0.10%) |
| Duplicate rows dropped | 307,078 rows (10.86%) |
| Negative values in `Flow Duration` / rates dropped | 107 rows |
| **Final dataset** | **2,520,691 rows** |
| Class imbalance | BENIGN 83.1% vs. Heartbleed 11 rows (~190,000 : 1) |

Inf values appear when `Flow Duration` is 0 (division by zero). They are only 0.1% of the data, so rows were dropped instead of imputed.

**Feature selection (78 → 47 features + Label)**

- **8 zero-variance columns** removed (`Bwd PSH Flags`, `Bwd URG Flags` and the six `*Avg Bulk*` columns).
- **23 redundant columns** removed. Features with |r| > 0.95 were grouped into 14 connected components (via NetworkX) and one representative was kept per group. Examples: `Total Fwd/Backward Packets` vs. `Subflow Fwd/Bwd Packets`, the `Idle *` family, `Fwd Header Length` vs. its duplicate `.1` column.
- There was no overlap between the two criteria.

Most features are strongly right-skewed with heavy outliers, so log-scale histograms were used. The extreme-value flows were checked and found to be benign traffic, so they were kept.

### 2. Classification

- **Split:** stratified 64% train / 16% validation / 20% test.
- **Scaling:** `StandardScaler` fit on the training set only.
- **Imbalance:** `class_weight='balanced'`. SMOTE was ruled out as impractical at this dataset size.
- **Tuning:** because of runtime, Grid Search ran on a stratified 150k-row sample of the training set, optimising **macro F1**.
  - *Without CV:* every combination is trained on the sample and scored on the validation set.
  - *With CV:* `GridSearchCV` with 3-fold `KFold`. Plain `KFold` was used instead of `StratifiedKFold` because some classes have fewer than 3 samples in the tuning sample.
- **Final models:** retrained on the full training set with the CV-selected hyperparameters and evaluated once on the untouched test set.

**Selected hyperparameters**

| Model | Grid | Without CV (validation) | With 3-fold CV |
|---|---|---|---|
| Logistic Regression | `C` ∈ {0.01, 0.1, 1, 10} | C=10 (F1-macro 0.468) | C=10 (CV F1-macro 0.427) |
| Decision Tree | depth ∈ {10, 20, 30, None}, min_split ∈ {2, 10, 50}, criterion ∈ {gini, entropy} | entropy, depth 30, split 2 (0.792) | entropy, depth 30, split 2 (CV 0.749) |
| Random Forest | trees ∈ {50, 100, 150}, depth ∈ {15, 25, None}, min_split ∈ {2, 10} | 50 trees, depth 25, split 10 (0.772) | 100 trees, depth 25, split 10 (CV 0.794) |

The Random Forest grid was reduced in the CV scenario (12 combinations instead of 18) to keep runtime manageable.

**Final test-set performance (504,139 flows)**

| Model | Accuracy | Precision (macro) | Recall (macro) | F1 (macro) | F1 (weighted) |
|---|---|---|---|---|---|
| Logistic Regression | 0.8477 | 0.3841 | 0.8772 | 0.4614 | 0.8949 |
| Decision Tree | 0.9983 | 0.8836 | 0.8695 | **0.8738** | 0.9984 |
| Random Forest | **0.9985** | **0.9250** | 0.8417 | 0.8594 | **0.9985** |

**Takeaways**

- Accuracy is misleading here: Logistic Regression reaches 85% accuracy but only 0.46 macro F1. With balanced class weights it flags nearly everything as an attack (recall 0.88, precision 0.38).
- Tree-based models separate the high-volume attacks (DDoS, DoS Hulk, PortScan, FTP/SSH-Patator, DoS variants) almost perfectly.
- The hard classes are the rare ones: **Web Attack XSS / SQL Injection, Bot, Infiltration, Heartbleed**. They have only a handful of test samples, so their scores are noisy.
- Decision Tree and Random Forest are close. Random Forest is more precise; the Decision Tree has slightly higher macro recall and F1.
- Hyperparameter choices were mostly stable between the two tuning approaches. The main difference was Random Forest (50 vs. 100 trees). The validation-set approach is cheaper but its score is tied to one split, while CV gives a more stable estimate on a sample with very rare classes.

### 3. Clustering

`Label` is **not** used for fitting, only to interpret the results afterwards. Clustering was done on a stratified **50,000-row sample** of the cleaned data (5,000 rows for the O(n²) hierarchical comparison).

| Algorithm | Configuration | Clusters | Silhouette | Davies–Bouldin |
|---|---|---|---|---|
| K-Means | k=2 (best silhouette over k=2…15) | 2 | 0.531 | 1.643 |
| K-Means | k=15 (compared with the 15 true classes) | 15 | 0.389 | 0.990 |
| Hierarchical | Ward, k=2 (5k sample) | 2 | 0.514 | 1.404 |
| DBSCAN | eps=2.0, min_samples=20 | 29 (+5.1% noise) | 0.391 | 0.608 |

**Takeaways**

- Complete and average linkage scored a Silhouette of 0.905, but produced **degenerate clusters** (4,997 / 1 / 2 points). Ward was chosen because its clusters are more balanced and interpretable. The metric alone would have picked a useless solution.
- K-Means with k=2 does **not** split benign from malicious traffic. It separates traffic profiles: DoS Hulk lands mostly in one cluster, while benign traffic, PortScan, brute-force and Bot flows share the other. Low-volume attacks look very similar to normal traffic in this feature space.
- DBSCAN works best as an **anomaly detector**: the noise points are concentrated in slow or rare attacks (DoS slowloris 57%, GoldenEye 35%, Slowhttptest 35%, the single Infiltration flow) versus 5.3% of benign traffic.
- The first two PCA components explain only 28% of the variance, so 2D plots are only a rough picture of the cluster structure.

---

## Setup

The notebook was developed and run on **Google Colab**.

### 1. Install dependencies

```bash
pip install pandas numpy scikit-learn scipy networkx matplotlib seaborn kaggle
```

### 2. Get the dataset

Download it with the Kaggle API (requires a `kaggle.json` API token):

```bash
mkdir -p ~/.kaggle && cp kaggle.json ~/.kaggle/ && chmod 600 ~/.kaggle/kaggle.json
kaggle datasets download -d chethuhn/network-intrusion-dataset -p data
unzip -q data/network-intrusion-dataset.zip -d data/CIC-IDS-2017
```

Or download the CSVs manually from the links in [Dataset](#dataset).

### 3. Run

Open `DataMining_Project_DrougkaM_1100545.ipynb` and run the cells in order. In the notebook the data path is `/content/data/CIC-IDS-2017/`; change it if you are not on Colab.

**Resources:** the full dataset takes about 1.8 GB in memory before cleaning. Grid Search on Random Forest is the slowest step (~13 min without CV, ~7 min with CV on Colab).

---

## Limitations and possible improvements

- Hyperparameter tuning used a 150k-row sample, and clustering used 50k (5k for hierarchical), because of compute limits. Results on the full data could differ.
- Rare classes (Heartbleed, SQL Injection, Infiltration) have too few samples for reliable evaluation. Techniques like SMOTE on a subset, class-specific resampling or anomaly-detection approaches could help.
- Plain `KFold` rather than `StratifiedKFold` was used for CV on the tuning sample, so folds may not contain every rare class.
- Possible next steps: gradient boosting (XGBoost/LightGBM), feature importance analysis, and dimensionality reduction before clustering.

---

## Author

**Maria Drougka** — Computer Engineering & Informatics, University of Patras
