#!/usr/bin/env python3

import pandas as pd
import json
import sys

def load_data(path):
    data = []
    with open(path, 'r') as f:
        for l in f:
            data.append(json.loads(l))

    return pd.concat(pd.json_normalize(rd) for rd in data)


def analyze(df):
    columns_to_keep = [
        'variant',
        'sig_size_bytes',
        'sk_size_bytes',
        'pk_size_bytes',
        'keygen.mean_us',
        'sign.mean_us',
        'verify.mean_us',
    ]

    for c in df.columns:
        if c not in columns_to_keep:
            del df[c]

    return df


def print_latex_table(df, indentation=4):
    variant_macros = {
        'FAEST_128S': r'\faestls',
        'FAEST_128F': r'\faestlf',
        'FAEST_192S': r'\faestms',
        'FAEST_192F': r'\faestmf',
        'FAEST_256S': r'\faesths',
        'FAEST_256F': r'\faesthf',
        'FAEST_EM_128S': r'\faestEMls',
        'FAEST_EM_128F': r'\faestEMlf',
        'FAEST_EM_192S': r'\faestEMms',
        'FAEST_EM_192F': r'\faestEMmf',
        'FAEST_EM_256S': r'\faestEMhs',
        'FAEST_EM_256F': r'\faestEMhf',
    }
    indent = ' ' * indentation

    print('%%% START GENERATED TABLE %%%')
    print(r'\begin{table}[tp]')
    print(1 * indent + r'\centering')
    print(1 * indent + r'\lennart{We will update the numbers in this table!}')
    print(1 * indent + r'\caption{TODO}')
    print(1 * indent + r'\label{tab:TODO}')
    print(1 * indent + r'\begin{tabular}{')
    print(2 * indent + r'l')
    print(2 * indent + r'S[table-format=4, table-auto-round, group-minimum-digits=3]')
    print(2 * indent + r'S[table-format=6, table-auto-round, group-minimum-digits=3]')
    print(2 * indent + r'S[table-format=6, table-auto-round, group-minimum-digits=3]')
    print(2 * indent + r'S[table-format=2, table-auto-round, group-minimum-digits=3]')
    print(2 * indent + r'S[table-format=2, table-auto-round, group-minimum-digits=3]')
    print(2 * indent + r'S[table-format=5, table-auto-round, group-minimum-digits=3]')
    print(1 * indent + r'}')
    print(2 * indent + r'\toprule')
    print(2 * indent + r'\multicolumn{1}{c}{\multirow{2}{*}{Scheme}} & \multicolumn{3}{c}{Runtimes in \si{\micro\second}} & \multicolumn{3}{c}{Sizes in \si{\byte}} \\')
    print(2 * indent + r'\cmidrule(lr){2-4} \cmidrule(l){5-7}')
    print(2 * indent + r'    & {\(\keygen\)} & {\(\sign\)} & {\(\verify\)} & {\(\sk\)} & {\(\pk\)} & {Signature} \\')
    print(2 * indent + r'\midrule')
    for index, r in df.iterrows():
        if r['variant'] == 'FAEST_EM_128S':
            print(2 * indent + r'\midrule')

        line = 2 * indent
        line += f"\\({variant_macros[r['variant']]:10s}\\)"
        line += f" & {r['keygen.mean_us']:10f}"
        line += f" & {r['sign.mean_us']:16f}"
        line += f" & {r['verify.mean_us']:16f}"
        line += f" & {r['sk_size_bytes']:2d}"
        line += f" & {r['pk_size_bytes']:2d}"
        line += f" & {r['sig_size_bytes']:5d}"
        line += r" \\"
        print(line)
    print(2 * indent + r'\bottomrule')
    print(1 * indent + r'\end{tabular}')
    print(r'\end{table}')
    print('%%% END GENERATED TABLE %%%')


def main(argv):
    if len(argv) != 2:
        print(f'usage: {sys.argv[0]} <path>')
        exit(1)

    path = argv[1]

    data = load_data(path)
    data = analyze(data)
    #  print(data)
    print_latex_table(data)


if __name__ == '__main__':
    main(sys.argv)
