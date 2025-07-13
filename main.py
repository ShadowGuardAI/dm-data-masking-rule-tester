import argparse
import logging
import pandas as pd
from faker import Faker
import re

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize Faker for generating fake data
fake = Faker()

def setup_argparse():
    """
    Sets up the command-line argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Validates data masking rules against a sample dataset.")
    parser.add_argument("data_file", help="Path to the CSV data file.")
    parser.add_argument("rule_file", help="Path to the JSON rule file.")
    parser.add_argument("--output", help="Path to save the masked data (optional).", default=None)  # Corrected typo
    return parser

def load_data(data_file):
    """
    Loads data from a CSV file using pandas.

    Args:
        data_file (str): Path to the CSV file.

    Returns:
        pandas.DataFrame: The loaded DataFrame.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        pd.errors.EmptyDataError: If the file is empty.
        pd.errors.ParserError: If the file cannot be parsed as CSV.
    """
    try:
        df = pd.read_csv(data_file)
        logging.info(f"Successfully loaded data from {data_file}")
        return df
    except FileNotFoundError:
        logging.error(f"Error: Data file not found: {data_file}")
        raise
    except pd.errors.EmptyDataError:
        logging.error(f"Error: Data file is empty: {data_file}")
        raise
    except pd.errors.ParserError:
        logging.error(f"Error: Could not parse data file as CSV: {data_file}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading data: {e}")
        raise

def load_rules(rule_file):
    """
    Loads rules from a JSON file (simplified).

    Args:
        rule_file (str): Path to the rule file.  Expected to be a simple dictionary-like structure.  Example:
                           {
                              "email": "email",
                              "phone_number": "phone_number",
                              "credit_card": "credit_card_number",
                              "name": "name"
                           }

    Returns:
        dict: A dictionary containing the rules.  Keys are column names, values are faker functions.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        json.JSONDecodeError: If the file cannot be parsed as JSON.
        ValueError: If the rule file does not contain a dictionary.
    """
    try:
        import json
        with open(rule_file, 'r') as f:
            rules = json.load(f)
        if not isinstance(rules, dict):
            raise ValueError("Rule file must contain a dictionary.")
        logging.info(f"Successfully loaded rules from {rule_file}")
        return rules
    except FileNotFoundError:
        logging.error(f"Error: Rule file not found: {rule_file}")
        raise
    except json.JSONDecodeError:
        logging.error(f"Error: Could not parse rule file as JSON: {rule_file}")
        raise
    except ValueError as e:
        logging.error(f"Error: Invalid rule file content: {e}")
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading rules: {e}")
        raise

def mask_data(df, rules):
    """
    Applies data masking rules to the DataFrame.

    Args:
        df (pandas.DataFrame): The DataFrame to mask.
        rules (dict): A dictionary of masking rules (column name: faker function).

    Returns:
        pandas.DataFrame: The masked DataFrame.
    """
    masked_df = df.copy()  # Create a copy to avoid modifying the original DataFrame
    for column, rule in rules.items():
        if column in masked_df.columns:
            try:
                if rule == "email":
                    masked_df[column] = [fake.email() for _ in range(len(masked_df))]
                elif rule == "phone_number":
                    masked_df[column] = [fake.phone_number() for _ in range(len(masked_df))]
                elif rule == "credit_card_number":
                    masked_df[column] = [fake.credit_card_number() for _ in range(len(masked_df))]
                elif rule == "name":
                    masked_df[column] = [fake.name() for _ in range(len(masked_df))]
                elif rule == "ssn":
                    masked_df[column] = [fake.ssn() for _ in range(len(masked_df))] #example ssn implementation
                elif rule == "address":
                    masked_df[column] = [fake.address() for _ in range(len(masked_df))] #example address implementation
                else:
                    logging.warning(f"Unsupported masking rule '{rule}' for column '{column}'. Skipping.")
                    continue  # Skip to the next rule
                logging.info(f"Successfully applied masking rule '{rule}' to column '{column}'.")
            except AttributeError as e:
                 logging.error(f"Invalid Faker function '{rule}': {e}")
            except Exception as e:
                logging.error(f"Error applying masking rule '{rule}' to column '{column}': {e}")
        else:
            logging.warning(f"Column '{column}' not found in data. Skipping rule.")
    return masked_df

def validate_masking(original_df, masked_df, rules):
    """
    Validates that the masking rules were applied correctly (basic validation).
    More sophisticated validation (e.g., checking format) could be added.

    Args:
        original_df (pandas.DataFrame): The original DataFrame.
        masked_df (pandas.DataFrame): The masked DataFrame.
        rules (dict): The masking rules used.

    Returns:
        bool: True if validation passes, False otherwise.
    """
    validation_errors = []
    for column, rule in rules.items():
        if column in original_df.columns and column in masked_df.columns:
            # Check for changes in the column
            if not original_df[column].equals(masked_df[column]):
                logging.info(f"Column '{column}' was successfully masked.")

                # Add a simple regex based validation check to confirm data is masked correctly
                if rule == "email":
                    email_regex = r"[^@]+@[^@]+\.[^@]+"
                    if not all(re.match(email_regex, str(email)) for email in masked_df[column]):
                        validation_errors.append(f"Column '{column}': Masked values do not conform to email format.")
                elif rule == "phone_number":
                    phone_regex = r"^\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}$"  # Simple phone number regex
                    if not all(re.match(phone_regex, str(phone)) for phone in masked_df[column]):
                        validation_errors.append(f"Column '{column}': Masked values do not conform to phone number format.")
                elif rule == "credit_card_number":
                    credit_card_regex = r"^\d{13,19}$" #Simple credit card format
                    if not all(re.match(credit_card_regex, str(credit)) for credit in masked_df[column]):
                        validation_errors.append(f"Column '{column}': Masked values do not conform to credit card format.")
                elif rule == "name":
                    name_regex = r"^[a-zA-Z\s]+$" #Simple name regex
                    if not all(re.match(name_regex, str(name)) for name in masked_df[column]):
                        validation_errors.append(f"Column '{column}': Masked values do not conform to name format.")
                elif rule == "ssn":
                    ssn_regex = r"^\d{3}-\d{2}-\d{4}$"
                    if not all(re.match(ssn_regex, str(ssn)) for ssn in masked_df[column]):
                        validation_errors.append(f"Column '{column}': Masked values do not conform to SSN format.")
                elif rule == "address":
                    # This is a very basic check; more detailed address validation is complex
                    address_regex = r"^[a-zA-Z0-9\s,'.-]+$"
                    if not all(re.match(address_regex, str(address)) for address in masked_df[column]):
                         validation_errors.append(f"Column '{column}': Masked values do not conform to Address format.")
            else:
                validation_errors.append(f"Column '{column}': Masking failed (column is unchanged).")
        else:
            validation_errors.append(f"Column '{column}': Column not found in either original or masked dataset.")

    if validation_errors:
        logging.error("Validation failed. See errors below:")
        for error in validation_errors:
            logging.error(error)
        return False
    else:
        logging.info("Validation passed: All columns were successfully masked.")
        return True

def save_masked_data(df, output_file):
    """
    Saves the masked DataFrame to a CSV file.

    Args:
        df (pandas.DataFrame): The masked DataFrame.
        output_file (str): Path to the output CSV file.
    """
    try:
        df.to_csv(output_file, index=False)
        logging.info(f"Successfully saved masked data to {output_file}")
    except Exception as e:
        logging.error(f"Error saving masked data to {output_file}: {e}")

def main():
    """
    Main function to orchestrate the data masking and validation process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        data = load_data(args.data_file)
        rules = load_rules(args.rule_file)
        masked_data = mask_data(data, rules)
        validation_result = validate_masking(data, masked_data, rules)

        if args.output:
            save_masked_data(masked_data, args.output)
        else:
            if validation_result:
                logging.info("Data masking and validation successful.  No output file specified, so data not saved.")
            else:
                logging.error("Data masking or validation failed.  No output file specified, so data not saved.")

        if not validation_result:
            exit(1) #exit with non-zero code on failure.

    except FileNotFoundError:
        exit(1)
    except pd.errors.EmptyDataError:
        exit(1)
    except pd.errors.ParserError:
        exit(1)
    except ValueError:
        exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        exit(1)

if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Basic Usage:
#    python main.py data.csv rules.json
#    Assumes 'data.csv' is your CSV file and 'rules.json' contains the masking rules.
#    Prints validation results to the console.  Does not save the masked data.

# 2. With Output File:
#    python main.py data.csv rules.json --output masked_data.csv
#    Masks the data and saves it to 'masked_data.csv'.

# 3. Example data.csv
# name,email,phone_number,credit_card
# John Doe,john.doe@example.com,555-123-4567,1234567890123456
# Jane Smith,jane.smith@example.com,555-987-6543,9876543210987654

# 4. Example rules.json
# {
#  "email": "email",
#  "phone_number": "phone_number",
#  "credit_card": "credit_card_number",
#  "name": "name"
# }