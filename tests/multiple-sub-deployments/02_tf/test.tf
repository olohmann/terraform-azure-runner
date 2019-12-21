provider "azurerm" {
  version = ">=1.38.0"
}

variable "rg_name" {
  type = string
}

data "azurerm_resource_group" "rg" {
  name = var.rg_name
}

locals {
  pseudo_random_value = substr(sha256(data.azurerm_resource_group.rg.id), 0, 10)
}

resource "azurerm_storage_account" "sa" {
  name                     = "sa${local.pseudo_random_value}"
  resource_group_name      = data.azurerm_resource_group.rg.name
  location                 = data.azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "GRS"

  tags = {
    environment = "staging"
  }
}
