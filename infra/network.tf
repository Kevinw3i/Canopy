# ── Network Selection ───────────────────────────────────

locals {
  network_vpc_id             = var.create_vpc ? aws_vpc.main[0].id : var.vpc_id
  network_public_subnet_ids  = var.create_vpc ? aws_subnet.public[*].id : var.public_subnet_ids
  network_private_subnet_ids = var.create_vpc ? aws_subnet.private[*].id : var.private_subnet_ids
  nat_gateway_count          = var.single_nat_gateway ? 1 : length(var.private_subnet_cidrs)
}

data "aws_availability_zones" "available" {
  count = var.create_vpc ? 1 : 0
  state = "available"
}

# ── VPC ─────────────────────────────────────────────────

resource "aws_vpc" "main" {
  count = var.create_vpc ? 1 : 0

  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  lifecycle {
    precondition {
      condition     = var.single_nat_gateway || length(var.public_subnet_cidrs) >= length(var.private_subnet_cidrs)
      error_message = "public_subnet_cidrs must contain at least as many CIDR blocks as private_subnet_cidrs when single_nat_gateway = false."
    }
  }

  tags = {
    Name = "${var.project}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  count = var.create_vpc ? 1 : 0

  vpc_id = aws_vpc.main[0].id

  tags = {
    Name = "${var.project}-igw"
  }
}

# ── Subnets ─────────────────────────────────────────────

resource "aws_subnet" "public" {
  count = var.create_vpc ? length(var.public_subnet_cidrs) : 0

  vpc_id                  = aws_vpc.main[0].id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available[0].names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project}-public-${count.index + 1}"
    Tier = "public"
  }
}

resource "aws_subnet" "private" {
  count = var.create_vpc ? length(var.private_subnet_cidrs) : 0

  vpc_id                  = aws_vpc.main[0].id
  cidr_block              = var.private_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available[0].names[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project}-private-${count.index + 1}"
    Tier = "private"
  }
}

# ── NAT Gateway ─────────────────────────────────────────

resource "aws_eip" "nat" {
  count = var.create_vpc ? local.nat_gateway_count : 0

  domain = "vpc"

  tags = {
    Name = "${var.project}-nat-eip-${count.index + 1}"
  }
}

resource "aws_nat_gateway" "main" {
  count = var.create_vpc ? local.nat_gateway_count : 0

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[var.single_nat_gateway ? 0 : count.index].id

  tags = {
    Name = "${var.project}-nat-${count.index + 1}"
  }

  depends_on = [aws_internet_gateway.main]
}

# ── Route Tables ────────────────────────────────────────

resource "aws_route_table" "public" {
  count = var.create_vpc ? 1 : 0

  vpc_id = aws_vpc.main[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main[0].id
  }

  tags = {
    Name = "${var.project}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count = var.create_vpc ? length(var.public_subnet_cidrs) : 0

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_route_table" "private" {
  count = var.create_vpc ? local.nat_gateway_count : 0

  vpc_id = aws_vpc.main[0].id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }

  tags = {
    Name = "${var.project}-private-rt-${count.index + 1}"
  }
}

resource "aws_route_table_association" "private" {
  count = var.create_vpc ? length(var.private_subnet_cidrs) : 0

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[var.single_nat_gateway ? 0 : count.index].id
}
