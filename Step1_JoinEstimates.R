# Load the necessary packages
library(dplyr)
library(readr)
library(tidyr)
library(openxlsx)


library(readr)


# Define the directory where the .csv files are located
input_directory <- "D:/OneDrive - IPAM-Amazonia/1_BKP_Git/2026/R/Proj_priv/data-2026-Nov-2026-v99/" # modify according to the path of the folder with the files
output_file <- paste0(input_directory,"//Step 3.1 - CarbonEmissionsPara_2018_2026.xlsx")

# List all CSV files in the directory
files <- list.files(input_directory, pattern = "*.csv", full.names = TRUE)


for (file in files) {
  cat("\nFile:", basename(file), "\n")
  df <- read_csv(file, show_col_types = FALSE)
  print(names(df))
}

process_file <- function(file_path) {
  
  # Read CSV
  df <- read_csv(file_path, show_col_types = FALSE)
  
  # Remove .geo column if it exists
  df <- df %>%
    select(-any_of(".geo"))
  
  # Extract file name
  file_name <- basename(file_path)
  
  # Extract identifiers
  parts <- strsplit(file_name, "_")[[1]]
  
  disturbance <- parts[1]
  type <- parts[2]
  gas <- parts[3]
  year_ok <- tools::file_path_sans_ext(parts[4])
  
  # Check whether sum exists
  if (!"sum" %in% names(df)) {
    stop(paste("Column 'sum' not found in file:", file_name,
               "\nAvailable columns:", paste(names(df), collapse = ", ")))
  }
  
  # Add identifiers and select columns
  df <- df %>%
    mutate(
      Disturbance = disturbance,
      Type = type,
      Gas = gas,
      Year = year_ok
    ) %>%
    #select(id_ok, Disturbance, Type, Gas, Year, sum) %>%
    select(idKey, Name, idKy_nm, src_fil, src_lyr, Disturbance, Type, Gas, Year, sum) %>%
    rename(CO2e_Emission = sum)
  
  return(df)
}


combined_data <- bind_rows(lapply(files, process_file))

#write.xlsx(combined_data, output_file)






df_apd <- read.csv("C:/Users/edriano.souza/Downloads/1-df_full_raw_br_verra_20261103.csv", comment.char="#")


# Unir - JOIN df_frel and df_apd
df_final <- combined_data %>%
  #mutate(idKey = as.integer(id_ok)) %>%
  left_join(
    df_apd,
    by = c("idKey" = "projectId")
  )





df_celso <- df_final %>%
  group_by(idKey, Disturbance, Type, Year, projectName,
           status,
           methodologies,
           vcsProjectId,
           latitudeLongitude,
           proponents,
           afoluNames,
           avgAnnualVolVcu) %>%
  summarise(
    Emissao_Total = sum(CO2e_Emission, na.rm = TRUE),
    .groups = "drop"
  )
