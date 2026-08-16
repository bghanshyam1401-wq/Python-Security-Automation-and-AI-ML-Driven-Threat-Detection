import pandas as pd
from scipy.io import arff

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import IsolationForest

from sklearn.metrics import (
    accuracy_score,
    classification_report
)

print("Loading dataset...\n")

data, meta = arff.loadarff(
    "dataset/Training Dataset.arff"
)

df = pd.DataFrame(data)

for column in df.columns:
    if df[column].dtype == object:
        df[column] = df[column].str.decode("utf-8")

print("First Five Rows")
print(df.head())

print("\nClass Distribution")
print(df.iloc[:, -1].value_counts())

before_rows = len(df)

df = df.dropna()

df = df.drop_duplicates()
import pandas as pd
from scipy.io import arff

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    precision_score,
    recall_score,
    f1_score
)


print("Loading dataset...\n")

# Load the UCI phishing dataset from the local ARFF file.
data, meta = arff.loadarff(
    "dataset/Training Dataset.arff"
)

df = pd.DataFrame(data)

# Decode byte-based categorical values imported from the ARFF file.
for column in df.columns:
    if df[column].dtype == object:
        df[column] = df[column].str.decode("utf-8")

print("First Five Rows")
print(df.head())

target_column = df.columns[-1]

print("\nClass Distribution Before Preprocessing")
print(df[target_column].value_counts())

original_rows = len(df)

# Remove null rows as required by the assignment.
df = df.dropna()

rows_after_null_removal = len(df)
null_rows_removed = original_rows - rows_after_null_removal

# Remove duplicate rows and calculate exactly how many were removed.
df = df.drop_duplicates()

final_rows = len(df)
duplicates_removed = rows_after_null_removal - final_rows

print(f"\nNull Rows Removed: {null_rows_removed}")
print(f"Duplicates Removed: {duplicates_removed}")
print(f"Rows Remaining: {final_rows}")

print("\nClass Distribution After Preprocessing")
print(df[target_column].value_counts())

X = df.drop(columns=[target_column])
y = df[target_column]

# Encode any categorical feature columns that may remain after ARFF loading.
X = pd.get_dummies(X, drop_first=False)

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\nTraining Random Forest...\n")

# Default model hyperparameters are used as required by the assignment.
random_forest = RandomForestClassifier(
    random_state=42
)

random_forest.fit(X_train, y_train)

rf_predictions = random_forest.predict(X_test)

rf_accuracy = accuracy_score(
    y_test,
    rf_predictions
)

rf_precision = precision_score(
    y_test,
    rf_predictions,
    average="weighted",
    zero_division=0
)

rf_recall = recall_score(
    y_test,
    rf_predictions,
    average="weighted",
    zero_division=0
)

rf_f1 = f1_score(
    y_test,
    rf_predictions,
    average="weighted",
    zero_division=0
)

print(f"Random Forest Accuracy:  {rf_accuracy:.4f}")
print(f"Random Forest Precision: {rf_precision:.4f}")
print(f"Random Forest Recall:    {rf_recall:.4f}")
print(f"Random Forest F1 Score:  {rf_f1:.4f}")

print("\nFull Random Forest Classification Report")

print(
    classification_report(
        y_test,
        rf_predictions,
        zero_division=0
    )
)

print("\nTraining Isolation Forest...\n")

minority_class = y.value_counts().idxmin()
minority_ratio = y.value_counts().min() / len(y)

print(f"Minority Class Treated as Anomaly: {minority_class}")
print(f"Minority Class Ratio: {minority_ratio:.4f}")

# Isolation Forest uses -1 for anomalies and 1 for normal observations.
y_anomaly = y.apply(
    lambda label: -1 if label == minority_class else 1
)

isolation_forest = IsolationForest(
    contamination=minority_ratio,
    random_state=42
)

isolation_forest.fit(X)

iso_predictions = isolation_forest.predict(X)

iso_accuracy = accuracy_score(
    y_anomaly,
    iso_predictions
)

iso_precision = precision_score(
    y_anomaly,
    iso_predictions,
    pos_label=-1,
    zero_division=0
)

iso_recall = recall_score(
    y_anomaly,
    iso_predictions,
    pos_label=-1,
    zero_division=0
)

iso_f1 = f1_score(
    y_anomaly,
    iso_predictions,
    pos_label=-1,
    zero_division=0
)

print(f"\nIsolation Forest Accuracy:  {iso_accuracy:.4f}")
print(f"Isolation Forest Precision: {iso_precision:.4f}")
print(f"Isolation Forest Recall:    {iso_recall:.4f}")
print(f"Isolation Forest F1 Score:  {iso_f1:.4f}")

print("\nModel Comparison")
print("-" * 88)
print(
    f"{'Model':<20}"
    f"{'Accuracy':<12}"
    f"{'Precision':<12}"
    f"{'Recall':<12}"
    f"{'F1 Score':<12}"
    f"{'Notes'}"
)
print("-" * 88)

print(
    f"{'Random Forest':<20}"
    f"{rf_accuracy:<12.4f}"
    f"{rf_precision:<12.4f}"
    f"{rf_recall:<12.4f}"
    f"{rf_f1:<12.4f}"
    f"Supervised classification"
)

print(
    f"{'Isolation Forest':<20}"
    f"{iso_accuracy:<12.4f}"
    f"{iso_precision:<12.4f}"
    f"{iso_recall:<12.4f}"
    f"{iso_f1:<12.4f}"
    f"Unsupervised anomaly detection"
)
