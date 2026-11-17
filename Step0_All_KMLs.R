library(sf)
library(dplyr)
library(purrr)
library(stringr)
library(tibble)

path <- "D:/OneDrive - IPAM-Amazonia/2026/04-2026-PrivateKMLs/Source-Join-KMLs"
setwd(path)

kml_files <- list.files(path, pattern = "\\.kml$", full.names = TRUE, ignore.case = TRUE)

# Função de leitura: lê TODAS as camadas e padroniza a geometria
read_kml <- function(f) {
  lyrs <- st_layers(f)$name
  
  map(lyrs, function(l) {
    x <- st_read(f, layer = l, quiet = TRUE)
    if (nrow(x) == 0) return(NULL)
    
    x <- x |>
      st_zm(drop = TRUE, what = "ZM") |>          # remove Z/M
      st_make_valid() |>                           # corrige geometrias inválidas
      st_collection_extract("POLYGON") |>          # remove sobras (linhas/pontos) de GEOMETRYCOLLECTION
      st_cast("MULTIPOLYGON")                      # harmoniza: tudo MULTIPOLYGON
    
    x$source_file <- basename(f)
    x$source_layer <- l
    x
  }) |> compact()
}

kmls <- map(kml_files, read_kml) |> list_flatten()

# Junta tudo
kml_all <- bind_rows(kmls)

# idKey = dígitos antes do primeiro "-" no nome do arquivo
kml_all <- kml_all |>
  mutate(
    idKey = str_extract(source_file, "^\\d+"),     # character (preserva zeros à esquerda)
    idKey_num = as.integer(idKey)
  ) |>
  relocate(idKey, idKey_num, source_file, source_layer)

# Checagens
nrow(kml_all)
table(st_geometry_type(kml_all))
all(st_is_valid(kml_all))
sum(is.na(kml_all$idKey))          # deve ser 0
n_distinct(kml_all$idKey)





##################


# Colunas por arquivo/camada
cols_por_arquivo <- map_dfr(kmls, function(x) {
  tibble(
    source_file = x$source_file[1],
    source_layer = x$source_layer[1],
    n_feat = nrow(x),
    n_cols = ncol(x) - 1,                            # sem geometria
    cols = paste(setdiff(names(x), attr(x, "sf_column")), collapse = " | ")
  )
})

# Variações de conjuntos de colunas
cols_por_arquivo |> count(cols, sort = TRUE) |> print(n = 20, width = Inf)

# Matriz presença/ausência de cada coluna por arquivo
all_cols <- sort(unique(unlist(map(kmls, \(x) setdiff(names(x), attr(x, "sf_column"))))))
presenca <- map_dfr(kmls, function(x) {
  setNames(as.list(all_cols %in% names(x)), all_cols) |>
    as_tibble() |>
    mutate(source_file = x$source_file[1], .before = 1)
})
View(presenca)

# Colunas finais vs. esperadas
setdiff(all_cols, names(kml_all))   # deve ser character(0)

kml_all$Description[1:3]


kmls <- map(kmls, \(x) x |> mutate(across(-geometry, as.character)))




##########AREA

library(ggplot2)

ggplot(kml_all) +
  geom_sf(aes(fill = AREA_CALC), color = "grey20", linewidth = 0.1) +
  scale_fill_viridis_c(option = "D", trans = "log10", name = "Área (ha)") +
  theme_minimal() +
  labs(title = "Áreas de projeto - KMLs",
       subtitle = paste0(nrow(kml_all), " features | ", n_distinct(kml_all$idKey), " idKeys"))







# Pasta de saída
out_dir <- "D:/OneDrive - IPAM-Amazonia/2026/04-2026-PrivateKMLs/Output"
dir.create(out_dir, showWarnings = FALSE, recursive = TRUE)



library(sf)
library(dplyr)

# Pasta de saída
out_dir <- "D:/OneDrive - IPAM-Amazonia/2026/04-2026-PrivateKMLs/Output"
dir.create(out_dir, showWarnings = FALSE, recursive = TRUE)



# Renomear para respeitar o limite de 10 caracteres
kml_shp <- kml_all |>
  rename(
    idKey     = idKey,
    idKey_num = idKey_num,
    src_file  = source_file,
    src_layer = source_layer
    
  )


# Escrever o shapefile (mantém WGS84 / EPSG:4326)
st_write(
  kml_shp,
  dsn = file.path(out_dir, "B-Verra-PARA-16-11-2026.shp"),
  delete_layer = TRUE,
  layer_options = "ENCODING=UTF-8"
)



