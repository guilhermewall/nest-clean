import { HttpException } from "@nestjs/common";
import { HttpStatus } from "@nestjs/common";
import { Body, Controller, HttpCode, Post } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { hash } from "bcryptjs";

@Controller("/account")
export class CreateAccountController {
  //como esse controller vai utilizar do prisma entao devo chamar no contructor da class
  constructor(private prisma: PrismaService) {}

  @Post()
  @HttpCode(201)
  async handle(@Body() body: any) {
    const { name, email, password } = body;

    const findUser = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (findUser) {
      throw new HttpException(
        "User with same e-mail address already exists.",
        HttpStatus.CONFLICT
      );
    }

    const hashPassword = await hash(password, 8);

    await this.prisma.user.create({
      data: {
        name,
        email,
        password: hashPassword,
      },
    });

    console.log(body);
  }
}