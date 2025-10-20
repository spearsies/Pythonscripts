<#
.DESCRIPTION
    The GhostTrace: AD Identity Scan.

.EXAMPLE
    Run Script without any parameters
    .\GhostTrace.ps1
.EXAMPLE


.LINK
    https://github.com/Bert-JanP/Incident-Response-Powershell

.NOTES
    The script imports data from a CSV to compare against Active Directory to see if the user exists, is active or not.


#>


$Version = '2.2.0'
$ASCIIBanner = @"
  ____           _                     _         ____                                       
 |  _ \    ___  | |__     __ _   ___  | |__     |  _ \    ___    __ _   _ __     ___   _ __ 
 | | | |  / _ \ | '_ \   / _` | / __| | '_ \    | |_) |  / _ \  / _` | | '_ \   / _ \ | '__|
 | |_| | |  __/ | | | | | (_| | \__ \ | | | |   |  _ <  |  __/ | (_| | | |_) | |  __/ | |   
 |____/   \___| |_| |_|  \__,_| |___/ |_| |_|   |_| \_\  \___|  \__,_| | .__/   \___| |_|   
                                                                       |_|                  
                    D e h a s h   R e a p e r   . p y


  DehashReaper.py - hunts through dehashed data, poetic and a bit grim.

"@
Write-Host $ASCIIBanner
Write-Host "Version: $Version"
Write-Host "By twitter: @spearsies, Github:"spearsies"
Write-Host "===========================================`n"



#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

import pandas as pd


def read_results_active_emails(results_file: Path, results_sheet: str) -> set:
    # Try with headers first
    try:
        df = pd.read_excel(results_file, sheet_name=results_sheet, dtype=str, engine="openpyxl")
        cols_lower = {c.lower(): c for c in df.columns if isinstance(c, str)}
        if "email" in cols_lower and ("status" in cols_lower or "result" in cols_lower):
            email_col = cols_lower["email"]
            status_col = cols_lower.get("status", cols_lower.get("result"))
            status_series = df[status_col].fillna("").astype(str).str.strip()
            active = df.loc[status_series.str.casefold() == "exists (active)".casefold(), email_col]
            return set(active.fillna("").str.strip().str.casefold())
    except Exception:
        pass

    # Fallback: no headers (A=Email, B=Status)
    df = pd.read_excel(results_file, sheet_name=results_sheet, header=None, dtype=str, engine="openpyxl")
    if df.shape[1] < 2:
        raise ValueError("Results sheet must have at least two columns (Email in A, Status in B).")
    status_series = df.iloc[:, 1].fillna("").astype(str).str.strip()
    active = df.loc[status_series.str.casefold() == "exists (active)".casefold(), 0]
    return set(active.fillna("").str.strip().str.casefold())


def read_hybrid(hybrid_file: Path, hybrid_sheet: str | None) -> pd.DataFrame:
    suffix = hybrid_file.suffix.lower()
    if suffix == ".csv":
        return pd.read_csv(hybrid_file, dtype=str, keep_default_na=False)
    if suffix in {".xlsx", ".xls"}:
        return pd.read_excel(hybrid_file, sheet_name=hybrid_sheet, dtype=str, engine="openpyxl")
    raise ValueError(f"Unsupported HYBRID file type: {suffix}. Use .csv or .xlsx")


def get_email_series(df: pd.DataFrame) -> pd.Series:
    # Prefer named 'Email' column
    cols_lower = {c.lower(): c for c in df.columns if isinstance(c, str)}
    if "email" in cols_lower:
        return df[cols_lower["email"]].astype(str)
    # Fallback to column D (index 3)
    if df.shape[1] >= 4:
        return df.iloc[:, 3].astype(str)
    raise ValueError("Could not locate Email column (named 'Email' or at column D).")


def set_match_column_c(df: pd.DataFrame, mask: pd.Series) -> pd.DataFrame:
    # Ensure we have at least 3 columns; insert 'Match' at position 2 (column C)
    value = mask.map(lambda x: "match" if x else "")
    if df.shape[1] >= 3:
        # Overwrite/replace position 2 by reconstructing columns
        cols = list(df.columns)
        col_c_name = cols[2]
        df[col_c_name] = value
        # Ensure the column remains at position 2
        if list(df.columns).index(col_c_name) != 2:
            # Reorder just in case (rare)
            cols[2] = col_c_name
            df = df[cols]
        return df
    else:
        # Insert if fewer than 3 columns exist
        df.insert(loc=2, column="Match", value=value)
        return df


def main():
    parser = argparse.ArgumentParser(description="Mark 'match' in column C for emails existing in results with status EXISTS (ACTIVE).")
    parser.add_argument("--hybrid-file", type=Path, default=Path("HYBRID - Dehashed Data.csv"),
                        help="Path to HYBRID data file (.csv or .xlsx). Default: 'HYBRID - Dehashed Data.csv'")
    parser.add_argument("--hybrid-sheet", type=str, default=None,
                        help="Sheet name for HYBRID data if using Excel. If omitted, reads the first sheet or the specified one by default.")
    parser.add_argument("--results-file", type=Path, default=Path("HYBRID - Dehashed Data.xlsx"),
                        help="Path to Excel workbook that contains the 'results' sheet. Default: 'HYBRID - Dehashed Data.xlsx'")
    parser.add_argument("--results-sheet", type=str, default="results",
                        help="Sheet name containing results (Email in A, Status in B). Default: 'results'")
    parser.add_argument("--output", type=Path, default=None,
                        help="Optional output file path. If omitted, suffix '_with_matches' is added next to input.")
    args = parser.parse_args()

    try:
        active_emails = read_results_active_emails(args.results_file, args.results_sheet)
        if not active_emails:
            print("Warning: No active emails found with status 'EXISTS (ACTIVE)' in results.", file=sys.stderr)

        hybrid_df = read_hybrid(args.hybrid_file, args.hybrid_sheet)

        email_series = get_email_series(hybrid_df).fillna("").str.strip().str.casefold()
        mask = email_series.isin(active_emails)

        hybrid_df = set_match_column_c(hybrid_df, mask)

        # Derive output path
        if args.output:
            out_path = args.output
        else:
            base = args.hybrid_file
            if base.suffix.lower() == ".csv":
                out_path = base.with_name(f"{base.stem}_with_matches.csv")
            elif base.suffix.lower() in {".xlsx", ".xls"}:
                out_path = base.with_name(f"{base.stem}_with_matches.xlsx")
            else:
                out_path = base.with_name(f"{base.stem}_with_matches")

        # Write result
        if out_path.suffix.lower() == ".csv":
            hybrid_df.to_csv(out_path, index=False)
        elif out_path.suffix.lower() in {".xlsx", ".xls"}:
            # Write single sheet (HYBRID data) to Excel
            sheet_name = args.hybrid_sheet or "HYBRID - Dehashed Data"
            with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
                hybrid_df.to_excel(writer, index=False, sheet_name=sheet_name)
        else:
            # Default to CSV if unknown extension
            out_csv = out_path.with_suffix(".csv")
            hybrid_df.to_csv(out_csv, index=False)
            out_path = out_csv

        total_matches = int(mask.sum())
        print(f"Done. Wrote: {out_path}")
        print(f"Rows marked 'match' in column C: {total_matches}")

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
Install and run
python3 -m pip install --upgrade pandas openpyxl
If your HYBRID data is in CSV (recommended per your note):
python3 match_emails.py \
  --hybrid-file "HYBRID - Dehashed Data.csv" \
  --results-file "HYBRID - Dehashed Data.xlsx" \
  --results-sheet "results"
If your HYBRID data is in the Excel workbook on a sheet (e.g., HYBRID - Dehashed Data):
python3 match_emails.py \
  --hybrid-file "HYBRID - Dehashed Data.xlsx" \
  --hybrid-sheet "HYBRID - Dehashed Data" \
  --results-file "HYBRID - Dehashed Data.xlsx" \
  --results-sheet "results"
