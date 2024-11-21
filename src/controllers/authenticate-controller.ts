import {
  Body,
  Controller,
  HttpCode,
  Post,
  UnauthorizedException,
  UsePipes,
} from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { JwtService } from "@nestjs/jwt";
import { z } from "zod";
import { ZodValidationPipe } from "src/pipes/zod-validation-pipe";
import { compare } from "bcryptjs";

const sessionSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

type SessionSchemaType = z.infer<typeof sessionSchema>;

@Controller("/sessions")
export class AuthenticateController {
  //como esse controller vai utilizar do prisma entao devo chamar no contructor da class
  constructor(private jwt: JwtService, private prisma: PrismaService) {}

  @Post()
  @HttpCode(201)
  @UsePipes(new ZodValidationPipe(sessionSchema))
  async handle(@Body() body: SessionSchemaType) {
    const { email, password } = body;

    const user = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      throw new UnauthorizedException("User credentials do not match.");
    }

    const isPasswordValid = await compare(password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException("User credentials do not match.");
    }

    const accessToken = this.jwt.sign({ sub: user.id });

    return {
      access_token: accessToken,
    };
  }
}
