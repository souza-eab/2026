library(dplyr)
library(ggplot2)
library(scales)
library(stringr)
library(ggh4x)

#====================================================
# PREPARAÇÃO (APENAS REGISTERED E VERIFICATION)
#====================================================

df_plot <- df_celso %>%
  mutate(
    Year = as.numeric(Year),
    
    Type = factor(
      Type,
      levels = c("def", "fire", "sl")
    ),
    
    projectName_short = str_extract(
      projectName,
      "^\\S+(?:\\s+\\S+){0,3}"
    ),
    
    status_grp = case_when(
      
      status == "Registered" ~ "Registered",
      
      status %in% c(
        "Verification approval requested",
        "Registration and verification approval requested"
      ) ~ "Verification",
      
      TRUE ~ NA_character_
    )
  ) %>%
  
  filter(!is.na(status_grp)) %>%
  
  mutate(
    facet_label = paste0(
      projectName_short,
      "\nID: ",
      idKey
    )
  )

#====================================================
# CORES DOS STATUS
#====================================================

cores_status <- c(
  "Registered"   = "#2E8B57",
  "Verification" = "#377EB8"
)

#====================================================
# ORDEM DOS PAINÉIS
#====================================================

facet_info <- df_plot %>%
  distinct(
    facet_label,
    status_grp
  ) %>%
  arrange(
    status_grp,
    facet_label
  )

df_plot$facet_label <- factor(
  df_plot$facet_label,
  levels = facet_info$facet_label
)

#====================================================
# BASELINE
#====================================================

baseline_df <- df_plot %>%
  group_by(
    facet_label
  ) %>%
  summarise(
    baseline = first(avgAnnualVolVcu),
    .groups = "drop"
  )

baseline_df$facet_label <- factor(
  baseline_df$facet_label,
  levels = levels(df_plot$facet_label)
)

#====================================================
# STRIPS COLORIDAS
#====================================================

strip_cols <- cores_status[
  facet_info$status_grp
]

#====================================================
# LEGENDA DE STATUS
#====================================================

legenda_status <- data.frame(
  status_grp = factor(
    c(
      "Registered",
      "Verification"
    ),
    levels = c(
      "Registered",
      "Verification"
    )
  ),
  x = NA,
  y = NA
)

#====================================================
# GRÁFICO
#====================================================

ggplot(
  df_plot,
  aes(
    x = factor(Year),
    y = Emissao_Total,
    fill = Type
  )
) +
  
  geom_col(
    colour = "white",
    linewidth = 0.2
  ) +
  
  geom_hline(
    data = baseline_df,
    aes(yintercept = baseline),
    linetype = "dashed",
    linewidth = 0.5,
    colour = "black",
    inherit.aes = FALSE
  ) +
  
  geom_text(
    data = baseline_df,
    aes(
      x = Inf,
      y = baseline,
      label = paste0(
        "PDD_EAER = ",
        format(
          round(baseline, 0),
          big.mark = ".",
          decimal.mark = ","
        )
      )
    ),
    inherit.aes = FALSE,
    hjust = 1.02,
    vjust = -0.15,
    size = 2.2
  ) +
  
  geom_point(
    data = legenda_status,
    aes(
      x = x,
      y = y,
      colour = status_grp
    ),
    size = 4,
    inherit.aes = FALSE
  ) +
  
  facet_wrap2(
    ~ facet_label,
    scales = "free_y",
    ncol = 4,
    
    strip = strip_themed(
      background_x = elem_list_rect(
        fill = strip_cols,
        colour = "black",
        linewidth = 0.7
      )
    )
  ) +
  
  scale_fill_manual(
    values = c(
      "def"  = "#E64B35",
      "fire" = "#F0C419",
      "sl"   = "#1AA05D"
    ),
    name = "Driver"
  ) +
  
  scale_colour_manual(
    values = cores_status,
    name = "Project Status"
  ) +
  
  scale_y_continuous(
    labels = label_number(
      big.mark = ".",
      decimal.mark = ","
    )
  ) +
  
  labs(
    title = "Emission Trends by Driver (2018–2026)",
    subtitle = "Registered and Verification projects only",
    x = "Year",
    y = expression("Emissions (tCO"[2] * "e)")
  ) +
  
  guides(
    fill = guide_legend(order = 1),
    colour = guide_legend(order = 2)
  ) +
  
  theme_bw(base_size = 10) +
  
  theme(
    strip.text = element_text(
      size = 7,
      face = "bold",
      colour = "black"
    ),
    
    strip.background = element_blank(),
    
    axis.text.x = element_text(
      angle = 90,
      vjust = 0.5
    ),
    
    legend.position = "top",
    legend.box = "vertical",
    
    panel.grid.minor = element_blank(),
    
    panel.spacing = unit(
      0.4,
      "lines"
    )
  )
