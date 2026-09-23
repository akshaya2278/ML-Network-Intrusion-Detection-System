from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer

def get_preprocessor(df):
    categorical_cols = ['protocol_type', 'service', 'flag']
    numerical_cols = [col for col in df.columns if col not in categorical_cols + ['label', 'attack_category', 'is_suspicious']]
    
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numerical_cols),
            ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), categorical_cols)
        ])
    
    return preprocessor, numerical_cols, categorical_cols