# Example usage: python gen_challenge.py /path/to/your/folder /path/to/your/output.txt
# Source files from https://github.com/bamman-group/gpt4-books/blob/main/data/model_output/chatgpt_results/
import os
import argparse

def process_files(folder_path, output_file):
    with open(output_file, 'w', encoding='utf-8') as output:
        for filename in os.listdir(folder_path):
            if filename.endswith('.txt'):
                file_path = os.path.join(folder_path, filename)
                with open(file_path, 'r', encoding='utf-8') as file:
                    for line in file:
                        columns = line.strip().split('\t')
                        if len(columns) == 4 and columns[1] == columns[2]:
                            output.write(f"{columns[1]}\t{columns[3]}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate challenges based on source files.')
    parser.add_argument('folder_path', type=str, help='Path to the folder')
    parser.add_argument('output_file', type=str, help='Path to the output file')
    args = parser.parse_args()

    process_files(args.folder_path, args.output_file)