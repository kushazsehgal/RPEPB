import pandas as pd
import matplotlib.pyplot as plt

def main():
    # 1. Read the CSV files
    scheme_df = pd.read_csv("scheme_times.csv")
    decoder_df = pd.read_csv("decoder_times.csv")
    
    # 2. Group by L, averaging over trials
    scheme_mean = scheme_df.groupby("L", as_index=False).mean(numeric_only=True)
    decoder_mean = decoder_df.groupby("L", as_index=False).mean(numeric_only=True)
    
    # Define which columns to plot for each CSV
    scheme_cols = [
        "setup_time_ms",
        "total_keygen_time_ms",
        "avg_keygen_time_ms",
        "aggregate_time_ms",
        "avg_enc_time_ms",
        "avg_indiv_decrypt_time_ms",
        "avg_combine_time_ms",
        "avg_total_decrypt_time_ms",
    ]
    decoder_cols = [
        "decoder_creation_time_ms",
        "trace_d_time_ms",
    ]
    
    # X values for the tick marks
    x_ticks = [16, 64, 256, 1024]
    
    # 3a. Plot scheme_times.csv in one figure
    plt.figure()
    for col in scheme_cols:
        plt.plot(scheme_mean["L"], scheme_mean[col], marker='o', label=col)
    plt.xscale("log")
    plt.yscale("log")
    # Force the x-axis to use exactly [16, 64, 256, 1024]
    plt.xticks(x_ticks, x_ticks)  
    plt.xlabel("Number of users (L) - log scale")
    plt.ylabel("Time (ms) - log scale")
    plt.title("Scheme Times vs. L (All columns)")
    plt.legend()
    plt.savefig("scheme_times_all_columns.png")
    plt.close()
    
    # 3b. Plot decoder_times.csv in one figure
    plt.figure()
    for col in decoder_cols:
        plt.plot(decoder_mean["L"], decoder_mean[col], marker='o', label=col)
    plt.xscale("log")
    plt.yscale("log")
    # Again, force x-axis to have ticks at [16, 64, 256, 1024]
    plt.xticks(x_ticks, x_ticks)
    plt.xlabel("Number of users (L) - log scale")
    plt.ylabel("Time (ms) - log scale")
    plt.title("Decoder Times vs. L (All columns)")
    plt.legend()
    plt.savefig("decoder_times_all_columns.png")
    plt.close()

if __name__ == "__main__":
    main()
