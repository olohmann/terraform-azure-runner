provider "azurerm" {
  version = ">=1.38.0"
}

variable "resource_group_name" {
    type = string
}

variable "resource_group_location" {
    type = string
    default = "North Europe"
}

resource "azurerm_resource_group" "rg" {
    name = var.resource_group_name
    location = var.resource_group_location
}

output "rg_name" {
  value = azurerm_resource_group.rg.name
}
