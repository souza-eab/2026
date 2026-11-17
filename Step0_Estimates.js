// =====================================================================
// emissoes_para_2018_2026.js  —  GEE Code Editor (JavaScript)
// Emissões de GEE (CO2, CH4, N2O em CO2eq) por desmatamento e degradação
// (fogo e exploração seletiva) no Pará, 2018–2026.
//
// Versão: v2.1 (2026-11-10)
// Histórico:
//   v1.0 — versão original (2018–2025), pasta Emissions_Para_v2.
//   v2.0 (2026-11-10)
//     - Inclui 2026: PRODES >6,25 ha preliminar
//       (yearly_deforestation_2026_pri_amazonia_legal_v20261015).
//     - Polígonos <6,25 ha mantidos como estavam (sem camada nova de 2026).
//     - 2026 só entra em pixels ainda sem desmatamento (não sobrescreve
//       anos anteriores).
//     - Verificação prévia dos assets de atividade 2026 (fogo e SL).
//     - Não carrega exploração seletiva de ANO_FINAL+1 (não existe).
//     - Exportações agrupadas em função auxiliar; opção de exportar
//       só a partir de um ano (EXPORTAR_A_PARTIR_DE).
//     - Saída na pasta Emissions_Para_v3.
//   v2.1 (2026-11-10)
//     - PRODES 2026 >6,25 ha: asset já codificado como 2026; filtro
//       simplificado para .eq(2026) (removida a alternativa 26).
//     - Removida a impressão dos metadados do asset 2026.
// =====================================================================

// ---------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------
var ANO_INICIAL = 2018;
var ANO_FINAL = 2026;              // inclusive
var EXPORTAR_A_PARTIR_DE = 2018;   // use 2026 para exportar só o ano novo
var PASTA = '2026-Nov-v99-Emissions_Para_Celso';
var BASE = 'projects/ee-ipam/assets/MRV_REDD_PARA/0_Activity_Year/';

// ---------------------------------------------------------------------
// Verificação dos assets necessários para 2026
// ---------------------------------------------------------------------
function existe(id) {
  try { ee.data.getAsset(id); return true; } catch (e) { return false; }
}
var ASSET_2026 = 'projects/ee-ipam/assets/yearly_deforestation_2026_pri_amazonia_legal_v20261015';
var necessarios = [
  ASSET_2026,
  BASE + 'degradation_2026_fire',
  BASE + 'degradation_2026_sl_disordered',
  BASE + 'degradation_2026_sl_geometric'
];
var faltando = necessarios.filter(function (id) { return !existe(id); });
if (faltando.length > 0) {
  print('ATENÇÃO — assets não encontrados:', faltando);
  throw new Error('Faltam assets de atividade para 2026: ' + faltando.join(', '));
}
print('Assets de 2026: OK');

// ---------------------------------------------------------------------
// Activity Data (2018–2023)
// ---------------------------------------------------------------------
var brazil_forests = ee.Image("projects/ee-ipam/assets/MRV_REDD_PARA/brazil_forest_pret_4Inv_v1"),
    ProdesLarger625ha = ee.Image("projects/ee-ipam/assets/MRV_REDD_PARA/PDigital2000_2023_AMZ_raster"),
    ProdesSmaller625ha = ee.Image("projects/ee-ipam/assets/MRV_REDD_PARA/yearly_deforestation_smaller_than_625ha_biome");

// Activity Data (2024)
var ProdesLarger625ha_2024 = ee.Image("projects/ee-ipam/assets/MRV_REDD_PARA/prodes_amazonia_legal_2024")
    .eq(24)
    .multiply(2024);
ProdesLarger625ha_2024 = ProdesLarger625ha_2024.updateMask(ProdesLarger625ha_2024.neq(0));

var ProdesSmaller625ha_2024 = ee.Image("projects/ee-ipam/assets/MRV_REDD_PARA/yearly_deforestation_2024_smaller_than_625ha_biome_proj")
    .eq(2024)
    .multiply(2024);
ProdesSmaller625ha_2024 = ProdesSmaller625ha_2024.updateMask(ProdesSmaller625ha_2024.neq(0));

// Activity Data (2025)
var ProdesLarger625ha_2025 = ee.Image("projects/ee-ipam/assets/MRV_REDD_PARA/prodes_amazonia_legal_2025_v20260408")
    .eq(25)
    .multiply(2025);
ProdesLarger625ha_2025 = ProdesLarger625ha_2025.updateMask(ProdesLarger625ha_2025.neq(0));

var ProdesSmaller625ha_2025 = ee.Image("projects/ee-ipam/assets/MRV_REDD_PARA/yearly_deforestation_smaller_than_625ha_biome_amazonia_v20260616_r")
    .eq(2025)
    .multiply(2025);
ProdesSmaller625ha_2025 = ProdesSmaller625ha_2025.updateMask(ProdesSmaller625ha_2025.neq(0));

// Activity Data (2026) — apenas polígonos >6,25 ha (PRODES preliminar)
// O asset já vem codificado com o valor 2026.
var ProdesLarger625ha_2026 = ee.Image(ASSET_2026).select(0)
    .eq(2026)
    .multiply(2026);
ProdesLarger625ha_2026 = ProdesLarger625ha_2026.updateMask(ProdesLarger625ha_2026.neq(0));

///// Emissions 2018–2026 //////////

// Pará State delimitation Projects Privates
//var para = ee.FeatureCollection("projects/ee-ipam/assets/PA_UF_2022"); // AOI -PA
// Aqui segue a nomenclatura para apenas para não alterar o código, todavia são os projetos privados
var para = ee.FeatureCollection("projects/ee-souza759/assets/CO2_proj_priv/proj_priv_sf_pa_v99-2026-Verra-PARA-16-11-2026"); // 
Map.addLayer(para, {}, "AOIs")

// Filtering the PRODES for forest areas (according to the 4th National GHG Inventory)
var aoi = para.geometry().bounds();
var mask = ee.Image(0).clip(aoi);

// Activity Data (Deforestation)
ProdesLarger625ha = ProdesLarger625ha
                  .remap([16,17,18,19,20,21,22,23], [2016,2017,2018,2019,2020,2021,2022,2023], 0);

var prodes_ate2025 = ProdesLarger625ha
                .blend(ProdesSmaller625ha)
                .blend(ProdesLarger625ha_2024)
                .blend(ProdesSmaller625ha_2024)
                .blend(ProdesLarger625ha_2025)
                .blend(ProdesSmaller625ha_2025);

// 2026 entra só onde ainda não há desmatamento registrado (2016–2025)
var livre = prodes_ate2025.unmask(0).eq(0);
var prodes_def = prodes_ate2025
                .blend(ProdesLarger625ha_2026.updateMask(livre))
                .multiply(brazil_forests)
                .clip(para);

prodes_def = mask.blend(prodes_def);

Map.centerObject(para, 6);
Map.addLayer(prodes_def.updateMask(prodes_def.gt(0)),
             {min: 2016, max: 2026, palette: ['#F0E442', '#E69F00', '#D55E00']},
             'Desmatamento 2016–2026');
Map.addLayer(prodes_def.eq(2026).selfMask().clip(para),
             {palette: ['#CC79A7']}, 'Desmatamento 2026 (>6,25 ha)');

// Carbon Map from the National FREL (Amazon EBA/INPE Map)
var agb = ee.Image('projects/ee-ipam/assets/MRV_REDD_PARA/EBA_AB_30m')
          .multiply(brazil_forests);
agb = agb.updateMask(agb.neq(-99999)) // -99999 represents nodata pixels
          .clip(para);

var bgb = ee.Image('projects/ee-ipam/assets/MRV_REDD_PARA/EBA_BB_30m')
          .multiply(brazil_forests);
bgb = bgb.updateMask(bgb.neq(-99999))
          .clip(para);

var dw = ee.Image('projects/ee-ipam/assets/MRV_REDD_PARA/EBA_DW_30m')
          .multiply(brazil_forests);
dw = dw.updateMask(dw.neq(-99999))
          .clip(para);

var litter = ee.Image('projects/ee-ipam/assets/MRV_REDD_PARA/EBA_LI_30m')
            .multiply(brazil_forests);
litter = litter.updateMask(litter.neq(-99999))
          .clip(para);

var agb_dw_l = agb.add(dw).add(litter);

////////////////////////////////////////////////////////////
////////// Calculating GHG emissions in CO2eq /////////////
//////////////////////////////////////////////////////////

// Activity Data (Degradation - Selective Logging)
// Selective Logging t0 (2018)
var sl_year_dis = ee.Image(BASE + "degradation_2017_sl_disordered")
              .multiply(brazil_forests)
              .clip(para);

var sl_year_geo = ee.Image(BASE + "degradation_2017_sl_geometric")
              .multiply(brazil_forests)
              .clip(para);

var sl_year = mask.blend(sl_year_dis).blend(sl_year_geo);

// Exporta a soma de uma imagem de emissões para o Pará
function exporta(img, nome) {
  var tabela = img.reduceRegions({
    collection: para,
    reducer: ee.Reducer.sum(), // Summing emissions for all pixels
    scale: 30
  });
  Export.table.toDrive({
    collection: tabela,
    folder: PASTA,
    description: nome,
    fileFormat: 'CSV'
  });
}

// Function to calculate CO2 emissions for a given year
function calculateCO2Emissions(Year) {

  /////// Fire emissions ///////
  var fire_year = ee.Image(BASE + 'degradation_' + Year + '_fire')
                .multiply(brazil_forests)
                .clip(para);
  fire_year = mask.blend(fire_year);

  var fire_co2 = agb.multiply(fire_year).multiply(0.368); // 44/12 - Carbon to CO2 conversion
  var fire_ch4 = agb_dw_l.multiply(fire_year).multiply(1/0.47).multiply(0.368).multiply(6.8).multiply(0.001); // CH4 to CO2 factor (IPCC, 2013 – AR5)
  var fire_n2o = agb_dw_l.multiply(fire_year).multiply(1/0.47).multiply(0.368).multiply(0.2).multiply(0.001); // N2O to CO2 factor (IPCC, 2013 – AR5)

  // Updating carbon stock (Fire)
  agb = agb.subtract(agb.multiply(fire_year).multiply(0.368));

  /////// Selective Logging emissions ///////
  var sl_factor_year = sl_year.remap([0,1,2,3,4,5,6,7,8,9,10], [0,0.29,0.27,0.26,0.22,0.22,0.22,0.22,0.22,0.22,0.22]); // Emission factors according to the number of selective logging occurrences
  var sl_co2 = agb.multiply(sl_factor_year);

  // Recorrência da exploração seletiva para o ano seguinte
  // (não carrega ANO_FINAL + 1, que ainda não existe)
  if (Year < ANO_FINAL) {
    var sl_next_dis = ee.Image(BASE + 'degradation_' + (Year + 1) + '_sl_disordered')
                .multiply(brazil_forests)
                .clip(para);
    var sl_next_geo = ee.Image(BASE + 'degradation_' + (Year + 1) + '_sl_geometric')
                .multiply(brazil_forests)
                .clip(para);

    var sl_year2 = mask.blend(sl_next_dis).blend(sl_next_geo);
    sl_year = sl_year.add(sl_year2).multiply(sl_year2);
  }

  // Updating carbon stock (Selective Logging)
  agb = agb.subtract(sl_co2);

  /////// Deforestation emissions ///////
  var deforestation_year = prodes_def.eq(Year);
  var def_co2 = bgb.add(agb_dw_l).multiply(deforestation_year);
  var def_ch4 = agb_dw_l.multiply(deforestation_year).multiply(1/0.47).multiply(0.368).multiply(6.8).multiply(0.001); // CH4 to CO2 factor (IPCC, 2013 – AR5)
  var def_n2o = agb_dw_l.multiply(deforestation_year).multiply(1/0.47).multiply(0.368).multiply(0.2).multiply(0.001); // N2O to CO2 factor (IPCC, 2013 – AR5)

  // Updating carbon stock (Deforestation)
  agb_dw_l = agb_dw_l.subtract(agb_dw_l.multiply(deforestation_year));
  agb = agb.subtract(agb.multiply(deforestation_year));
  bgb = bgb.subtract(bgb.multiply(deforestation_year));


  /////// Export GHG emissions as Table (.csv)
  if (Year >= EXPORTAR_A_PARTIR_DE) {
    var ha = ee.Image.pixelArea().multiply(0.0001);

    // Fire emissions
    exporta(fire_co2.multiply(ha).multiply(44/12), 'degradation_fire_co2_' + Year); // Carbon to CO2
    exporta(fire_ch4.multiply(ha).multiply(28),    'degradation_fire_ch4_' + Year); // CH4 GWP (AR5)
    exporta(fire_n2o.multiply(ha).multiply(265),   'degradation_fire_n2o_' + Year); // N2O GWP (AR5)

    // Selective Logging emissions
    exporta(sl_co2.multiply(ha).multiply(44/12),   'degradation_sl_co2_' + Year);

    // Deforestation emissions
    exporta(def_co2.multiply(ha).multiply(44/12),  'deforestation_def_co2_' + Year);
    exporta(def_ch4.multiply(ha).multiply(28),     'deforestation_def_ch4_' + Year);
    exporta(def_n2o.multiply(ha).multiply(265),    'deforestation_def_n2o_' + Year);
  }

  return Year + 1; // Return the next year
}

// Itera ANO_INICIAL..ANO_FINAL (inclusive)
function iterateYears(startYear, endYear) {
  if (startYear <= endYear) {
    var nextYear = calculateCO2Emissions(startYear);
    iterateYears(nextYear, endYear);
  }
}
iterateYears(ANO_INICIAL, ANO_FINAL); // 2018–2026
