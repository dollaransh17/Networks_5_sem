"""Preprocessing shared by the trusted CNS 2022 release artifacts."""

import pickle
from pathlib import Path


RELEASE_VERSION = "cns2022-v1.0.0"
XGBOOST_FILE = "xgboost_cns2022.pkl"
BILSTM_FILE = "bilstm_cns2022.pt"
ISOLATION_FOREST_FILE = "isolation_forest.pkl"
PREPROCESSING_FILE = "scaler_and_encoder.pkl"


def load_preprocessing(model_path):
    with Path(model_path).with_name(PREPROCESSING_FILE).open("rb") as source:
        return pickle.load(source)
